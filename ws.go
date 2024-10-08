package front

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"time"
	_ "unsafe"

	"github.com/gorilla/websocket"
	utils "github.com/qydysky/front/utils"
	component2 "github.com/qydysky/part/component2"
	pctx "github.com/qydysky/part/ctx"
	pslice "github.com/qydysky/part/slice"
	"golang.org/x/net/proxy"
)

func init() {
	type I interface {
		Deal(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error
	}
	if e := component2.Register[I]("ws", wsDealer{}); e != nil {
		panic(e)
	}
}

type wsDealer struct{}

func (wsDealer) Deal(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error {
	var (
		opT       = time.Now()
		resp      *http.Response
		conn      net.Conn
		errFormat = "%v %v > %v > %v ws %v %v"
	)

	// for i := 0; i < len(backs) && (resp == nil || conn == nil); i++ {
	// 	if !backs[i].IsLive() {
	// 		continue
	// 	}
	// 	chosenBack = backs[i]

	url := chosenBack.To
	if chosenBack.PathAdd() {
		url += r.RequestURI
	}

	url = "ws" + url

	url = dealUri(url, chosenBack.getDealerReqUri())

	reqHeader := make(http.Header)

	if e := copyHeader(r.Header, reqHeader, chosenBack.getDealerReqHeader()); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
		return ErrDealReqHeader
	}

	var e error
	conn, resp, e = DialContext(ctx, url, reqHeader, chosenBack)
	if e != nil && !errors.Is(e, context.Canceled) {
		logger.Warn(`W:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
		chosenBack.Disable()
		conn = nil
		resp = nil
	}

	if chosenBack.getErrToSec() != 0 && time.Since(opT).Seconds() > chosenBack.getErrToSec() {
		logger.Warn(`W:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, ErrResTO, time.Since(opT)))
		chosenBack.Disable()
		conn.Close()
		conn = nil
		resp = nil
	}
	// }

	if resp == nil || conn == nil {
		return ErrResFail
	}

	if pctx.Done(r.Context()) {
		return context.Canceled
	}

	if ok, e := chosenBack.getFiliterResHeader().Match(resp.Header); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
	} else if !ok {
		logger.Warn(`W:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, ErrHeaderCheckFail, time.Since(opT)))
		w.Header().Add(header+"Error", ErrHeaderCheckFail.Error())
		return ErrHeaderCheckFail
	}

	logger.Debug(`T:`, fmt.Sprintf("%v > %v > %v ws ok %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, time.Since(opT)))

	if chosenBack.route.RollRule != `` {
		chosenBack.be(opT)
		defer chosenBack.ed()
	}

	if chosenBack.Splicing() != 0 {
		cookie := &http.Cookie{
			Name:   "_psign_" + cookie,
			Value:  chosenBack.Id(),
			MaxAge: chosenBack.Splicing(),
			Path:   "/",
		}
		if utils.ValidCookieDomain(r.Host) {
			cookie.Domain = r.Host
		}
		w.Header().Add("Set-Cookie", (cookie).String())
	}

	w.Header().Add(header+"Info", cookie+";"+chosenBack.Name)

	defer conn.Close()

	resHeader := make(http.Header)
	if e := copyHeader(resp.Header, resHeader, chosenBack.getDealerResHeader()); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
		return ErrDealResHeader
	}

	if req, e := Upgrade(w, r, resHeader); e != nil {
		return ErrResDoFail
	} else {
		defer req.Close()

		select {
		case e := <-copyWsMsg(req, conn, blocksi):
			if e != nil {
				if !errors.Is(e, context.Canceled) {
					chosenBack.Disable()
				}
				logger.Error(`E:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
				return ErrCopy
			}
		case e := <-copyWsMsg(conn, req, blocksi):
			if e != nil {
				if !errors.Is(e, context.Canceled) {
					chosenBack.Disable()
				}
				logger.Error(`E:`, fmt.Sprintf(errFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
				return ErrCopy
			}
		case <-ctx.Done():
		}

		return nil
	}
}

func copyWsMsg(dst io.Writer, src io.Reader, blocksi pslice.BlocksI[byte]) <-chan error {
	c := make(chan error, 1)
	go func() {
		if tmpbuf, put, e := blocksi.Get(); e != nil {
			c <- e
		} else {
			defer put()
			_, e := io.CopyBuffer(dst, src, tmpbuf)
			c <- e
		}
	}()
	return c
}

func DialContext(ctx context.Context, urlStr string, requestHeader http.Header, chosenBack *Back) (net.Conn, *http.Response, error) {
	d := websocket.DefaultDialer

	challengeKey := requestHeader.Get("Sec-WebSocket-Key")

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, nil, err
	}

	switch u.Scheme {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	default:
		return nil, nil, utils.ErrMalformedURL
	}

	if u.User != nil {
		// User name and password are not allowed in websocket URIs.
		return nil, nil, utils.ErrMalformedURL
	}

	req := &http.Request{
		Method:     http.MethodGet,
		URL:        u,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       u.Host,
	}
	req = req.WithContext(ctx)

	// Set the request headers using the capitalization for names and values in
	// RFC examples. Although the capitalization shouldn't matter, there are
	// servers that depend on it. The Header.Set method is not used because the
	// method canonicalizes the header names.
	for k, vs := range requestHeader {
		req.Header[k] = vs
	}

	if d.HandshakeTimeout != 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, d.HandshakeTimeout)
		defer cancel()
	}

	// Get network dial function.
	var netDial func(network, add string) (net.Conn, error)

	switch u.Scheme {
	case "http":
		if d.NetDialContext != nil {
			netDial = func(network, addr string) (net.Conn, error) {
				return d.NetDialContext(ctx, network, addr)
			}
		} else if d.NetDial != nil {
			netDial = d.NetDial
		}
	case "https":
		if d.NetDialTLSContext != nil {
			netDial = func(network, addr string) (net.Conn, error) {
				return d.NetDialTLSContext(ctx, network, addr)
			}
		} else if d.NetDialContext != nil {
			netDial = func(network, addr string) (net.Conn, error) {
				return d.NetDialContext(ctx, network, addr)
			}
		} else if d.NetDial != nil {
			netDial = d.NetDial
		}
	default:
		return nil, nil, utils.ErrMalformedURL
	}

	if netDial == nil {
		netDialer := &net.Dialer{}
		netDial = func(network, addr string) (net.Conn, error) {
			return netDialer.DialContext(ctx, network, addr)
		}
	}

	// If needed, wrap the dial function to set the connection deadline.
	if deadline, ok := ctx.Deadline(); ok {
		forwardDial := netDial
		netDial = func(network, addr string) (net.Conn, error) {
			c, err := forwardDial(network, addr)
			if err != nil {
				return nil, err
			}
			err = c.SetDeadline(deadline)
			if err != nil {
				if err := c.Close(); err != nil {
					log.Printf("websocket: failed to close network connection: %v", err)
				}
				return nil, err
			}
			return c, nil
		}
	}

	// If needed, wrap the dial function to connect through a proxy.
	if d.Proxy != nil {
		proxyURL, err := d.Proxy(req)
		if err != nil {
			return nil, nil, err
		}
		if proxyURL != nil {
			dialer, err := proxy.FromURL(proxyURL, netDialerFunc(netDial))
			if err != nil {
				return nil, nil, err
			}
			netDial = dialer.Dial
		}
	}

	hostPort, hostNoPort := utils.HostPortNoPort(u)
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.GetConn != nil {
		trace.GetConn(hostPort)
	}

	netConn, err := netDial("tcp", hostPort)
	if err != nil {
		return nil, nil, err
	}
	if trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{
			Conn: netConn,
		})
	}

	if u.Scheme == "https" && d.NetDialTLSContext == nil {
		// If NetDialTLSContext is set, assume that the TLS handshake has already been done

		cfg := utils.CloneTLSConfig(d.TLSClientConfig)
		if cfg.ServerName == "" {
			cfg.ServerName = hostNoPort
		}
		cfg.InsecureSkipVerify = chosenBack.getInsecureSkipVerify()

		if cer, err := chosenBack.getVerifyPeerCer(); err == nil {
			pool := x509.NewCertPool()
			if pool.AppendCertsFromPEM(cer) {
				cfg.InsecureSkipVerify = true
				cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) (e error) {
					if len(rawCerts) == 0 {
						return ErrCerVerify
					}
					if serCer, err := x509.ParseCertificate(rawCerts[0]); err != nil {
						return err
					} else if _, err = serCer.Verify(x509.VerifyOptions{Intermediates: pool, Roots: pool}); err != nil {
						return err
					}
					return
				}
			} else {
				return nil, nil, ErrCerVerify
			}
		} else if err != ErrEmptyVerifyPeerCerByte {
			return nil, nil, err
		}

		tlsConn := tls.Client(netConn, cfg)
		netConn = tlsConn

		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := utils.DoHandshake(ctx, tlsConn, cfg)
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tlsConn.ConnectionState(), err)
		}

		if err != nil {
			return nil, nil, err
		}
	}

	if d.ReadBufferSize == 0 {
		d.ReadBufferSize = defaultReadBufferSize
	} else if d.ReadBufferSize < maxControlFramePayloadSize {
		// must be large enough for control frame
		d.ReadBufferSize = maxControlFramePayloadSize
	}
	br := bufio.NewReaderSize(netConn, d.ReadBufferSize)

	if err := req.Write(netConn); err != nil {
		return nil, nil, err
	}

	if trace != nil && trace.GotFirstResponseByte != nil {
		if peek, err := br.Peek(1); err == nil && len(peek) == 1 {
			trace.GotFirstResponseByte()
		}
	}

	resp, err := http.ReadResponse(br, req)
	if err != nil {
		if d.TLSClientConfig != nil {
			for _, proto := range d.TLSClientConfig.NextProtos {
				if proto != "http/1.1" {
					return nil, nil, fmt.Errorf(
						"websocket: protocol %q was given but is not supported;"+
							"sharing tls.Config with net/http Transport can cause this error: %w",
						proto, err,
					)
				}
			}
		}
		return nil, nil, err
	}

	if d.Jar != nil {
		if rc := resp.Cookies(); len(rc) > 0 {
			d.Jar.SetCookies(u, rc)
		}
	}

	if resp.StatusCode != 101 ||
		!utils.TokenListContainsValue(resp.Header, "Upgrade", "websocket") ||
		!utils.TokenListContainsValue(resp.Header, "Connection", "upgrade") ||
		resp.Header.Get("Sec-Websocket-Accept") != utils.ComputeAcceptKey(challengeKey) {
		// Before closing the network connection on return from this
		// function, slurp up some of the response to aid application
		// debugging.
		buf := make([]byte, 1024)
		n, _ := io.ReadFull(resp.Body, buf)
		resp.Body = io.NopCloser(bytes.NewReader(buf[:n]))
		log.Default().Println(resp.StatusCode, resp.Header)
		return nil, resp, websocket.ErrBadHandshake
	}

	resp.Body = io.NopCloser(bytes.NewReader([]byte{}))

	if err := netConn.SetDeadline(time.Time{}); err != nil {
		return nil, nil, err
	}
	return netConn, resp, nil
}

type netDialerFunc func(network, addr string) (net.Conn, error)

func (fn netDialerFunc) Dial(network, addr string) (net.Conn, error) {
	return fn(network, addr)
}

const (
	maxFrameHeaderSize         = 2 + 8 + 4 // Fixed header + length + mask
	defaultReadBufferSize      = 4096
	defaultWriteBufferSize     = 4096
	maxControlFramePayloadSize = 125
)

func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (net.Conn, error) {
	u := &websocket.Upgrader{}
	h, ok := w.(http.Hijacker)
	if !ok {
		return returnError(u, w, r, http.StatusInternalServerError, "websocket: response does not implement http.Hijacker")
	}
	var brw *bufio.ReadWriter
	netConn, brw, err := h.Hijack()
	if err != nil {
		return returnError(u, w, r, http.StatusInternalServerError, err.Error())
	}

	if brw.Reader.Buffered() > 0 {
		if err := netConn.Close(); err != nil {
			log.Printf("websocket: failed to close network connection: %v", err)
		}
		return nil, errors.New("websocket: client sent data before handshake is complete")
	}

	buf := utils.BufioWriterBuffer(netConn, brw.Writer)

	var writeBuf []byte
	if u.WriteBufferPool == nil && u.WriteBufferSize == 0 && len(buf) >= maxFrameHeaderSize+256 {
		// Reuse hijacked write buffer as connection buffer.
		writeBuf = buf
	} else {
		if u.WriteBufferSize <= 0 {
			u.WriteBufferSize = defaultWriteBufferSize
		}
		u.WriteBufferSize += maxFrameHeaderSize
		if u.WriteBufferPool == nil {
			writeBuf = make([]byte, u.WriteBufferSize)
		}
	}

	// Use larger of hijacked buffer and connection write buffer for header.
	p := buf
	if len(writeBuf) > len(p) {
		p = writeBuf
	}
	p = p[:0]

	p = append(p, "HTTP/1.1 101 Switching Protocols\r\n"...)
	for k, vs := range responseHeader {
		for _, v := range vs {
			p = append(p, k...)
			p = append(p, ": "...)
			for i := 0; i < len(v); i++ {
				b := v[i]
				if b <= 31 {
					// prevent response splitting.
					b = ' '
				}
				p = append(p, b)
			}
			p = append(p, "\r\n"...)
		}
	}
	p = append(p, "\r\n"...)

	// Clear deadlines set by HTTP server.
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		if err := netConn.Close(); err != nil {
			log.Printf("websocket: failed to close network connection: %v", err)
		}
		return nil, err
	}

	if u.HandshakeTimeout > 0 {
		if err := netConn.SetWriteDeadline(time.Now().Add(u.HandshakeTimeout)); err != nil {
			if err := netConn.Close(); err != nil {
				log.Printf("websocket: failed to close network connection: %v", err)
			}
			return nil, err
		}
	}
	if _, err = netConn.Write(p); err != nil {
		if err := netConn.Close(); err != nil {
			log.Printf("websocket: failed to close network connection: %v", err)
		}
		return nil, err
	}
	if u.HandshakeTimeout > 0 {
		if err := netConn.SetWriteDeadline(time.Time{}); err != nil {
			if err := netConn.Close(); err != nil {
				log.Printf("websocket: failed to close network connection: %v", err)
			}
			return nil, err
		}
	}

	return netConn, nil
}

func returnError(u *websocket.Upgrader, w http.ResponseWriter, r *http.Request, status int, reason string) (net.Conn, error) {
	err := HandshakeError{message: reason}
	if u.Error != nil {
		u.Error(w, r, status, err)
	} else {
		w.Header().Set("Sec-Websocket-Version", "13")
		http.Error(w, http.StatusText(status), status)
	}
	return nil, err
}

type HandshakeError struct {
	message string
}

func (t HandshakeError) Error() string {
	return t.message
}
