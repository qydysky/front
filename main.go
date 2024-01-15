package front

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
	_ "unsafe"

	"github.com/gorilla/websocket"
	pctx "github.com/qydysky/part/ctx"
	pslice "github.com/qydysky/part/slice"
	pweb "github.com/qydysky/part/web"
	"golang.org/x/net/proxy"
)

type Logger interface {
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

type File interface {
	Read(data []byte) (int, error)
}

//go:linkname validCookieDomain net/http.validCookieDomain
func validCookieDomain(v string) bool

// 加载
func LoadPeriod(ctx context.Context, buf []byte, configF File, configS *[]Config, logger Logger) error {
	if e := loadConfig(buf, configF, configS); e != nil {
		logger.Error(`E:`, "配置加载", e)
		return e
	}
	// 定时加载config
	go func() {
		ctx1, done1 := pctx.WaitCtx(ctx)
		defer done1()
		for {
			select {
			case <-time.After(time.Second * 10):
				if e := loadConfig(buf, configF, configS); e != nil {
					logger.Error(`E:`, "配置加载", e)
				}
			case <-ctx1.Done():
				return
			}
		}
	}()
	return nil
}

// 测试
func Test(ctx context.Context, port int, logger Logger) {
	if port == 0 {
		return
	}
	ctx1, done1 := pctx.WaitCtx(ctx)
	defer done1()
	logger.Info(`I:`, "启动", fmt.Sprintf("127.0.0.1:%d", port))
	s := pweb.New(&http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", port),
		WriteTimeout: time.Second * time.Duration(10),
	})
	defer s.Shutdown()
	s.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/`: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		},
	})
	<-ctx1.Done()
}

var cookie = fmt.Sprintf("%p", &struct{}{})

// 转发
func Run(ctx context.Context, configSP *Config, logger Logger) {
	// 根ctx
	ctx, cancle := pctx.WithWait(ctx, 0, time.Minute)
	defer func() {
		if errors.Is(cancle(), pctx.ErrWaitTo) {
			logger.Error(`E:`, "退出超时")
		}
	}()

	// 路由
	routeP := pweb.WebPath{}

	logger.Info(`I:`, "启动...")
	defer logger.Info(`I:`, "退出,等待1min连接关闭...")

	// config对象初次加载
	if e := applyConfig(ctx, configSP, &routeP, logger); e != nil {
		return
	}

	// matchfunc
	var matchfunc func(path string) (func(w http.ResponseWriter, r *http.Request), bool)
	switch configSP.MatchRule {
	case "prefix":
		logger.Info(`I:`, "匹配规则", "prefix")
		matchfunc = routeP.LoadPerfix
	case "all":
		logger.Info(`I:`, "匹配规则", "all")
		matchfunc = routeP.Load
	default:
		logger.Error(`E:`, "匹配规则", "无效")
		return
	}

	httpSer := http.Server{
		Addr: configSP.Addr,
	}

	if configSP.TLS.Config != nil {
		httpSer.TLSConfig = configSP.TLS.Config.Clone()
	}

	if configSP.BlocksI == nil {
		if configSP.CopyBlocks == 0 {
			configSP.CopyBlocks = 1000
		}
		configSP.BlocksI = pslice.NewBlocks[byte](16*1024, configSP.CopyBlocks)
	}

	syncWeb := pweb.NewSyncMap(&httpSer, &routeP, matchfunc)
	defer syncWeb.Shutdown()

	// 定时加载config
	for {
		select {
		case <-time.After(time.Second * 10):
			_ = applyConfig(ctx, configSP, &routeP, logger)
		case <-ctx.Done():
			return
		}
	}
}

func loadConfig(buf []byte, configF File, configS *[]Config) error {
	if i, e := configF.Read(buf); e != nil && !errors.Is(e, io.EOF) {
		return e
	} else if i == cap(buf) {
		return errors.New(`buf full`)
	} else {
		for i := 0; i < len(*configS); i++ {
			(*configS)[i].lock.Lock()
			defer (*configS)[i].lock.Unlock()
		}
		if e := json.Unmarshal(buf[:i], configS); e != nil {
			return e
		}
		for i := 0; i < len((*configS)); i++ {
			if (*configS)[i].TLS.Config == nil && (*configS)[i].TLS.Key != "" && (*configS)[i].TLS.Pub != "" {
				if cert, e := tls.LoadX509KeyPair((*configS)[i].TLS.Pub, (*configS)[i].TLS.Key); e != nil {
					return e
				} else {
					(*configS)[i].TLS.Config = &tls.Config{
						Certificates: []tls.Certificate{cert},
						NextProtos:   []string{"h2", "http/1.1"},
					}
				}
			}
		}
	}
	return nil
}

//go:linkname nanotime1 runtime.nanotime1
func nanotime1() int64

func applyConfig(ctx context.Context, configS *Config, routeP *pweb.WebPath, logger Logger) error {
	configS.lock.RLock()
	defer configS.lock.RUnlock()

	for i := 0; i < len(configS.Routes); i++ {
		route := &configS.Routes[i]
		path := route.Path

		if !route.SwapSign() {
			continue
		}

		if len(route.Back) == 0 {
			logger.Info(`I:`, "移除路由", path)
			routeP.Store(path, nil)
			continue
		}

		backArray := route.GenBack()

		if len(backArray) == 0 {
			logger.Info(`I:`, "移除路由", path)
			routeP.Store(path, nil)
			continue
		}

		backMap := make(map[string]*Back)

		for i := 0; i < len(backArray); i++ {
			backMap[backArray[i].Sign] = backArray[i]
		}

		logger.Info(`I:`, "路由更新", path)

		routeP.Store(path, func(w http.ResponseWriter, r *http.Request) {
			ctx1, done1 := pctx.WaitCtx(ctx)
			defer done1()

			var backIs []*Back
			if validCookieDomain(r.Host) {
				if t, e := r.Cookie("_psign_" + cookie); e == nil {
					if tmp, ok := backMap[t.Value]; ok {
						backIs = append(backIs, tmp)
					}
				}
			}

			if len(backIs) == 0 {
				backIs = append(backIs, FiliterBackByRequest(backArray, r)...)
			}

			if len(backIs) == 0 {
				w.WriteHeader(http.StatusServiceUnavailable)
				logger.Error(`W:`, fmt.Sprintf("%s=> 无可用后端", path))
				return
			}

			var e error
			if r.Header.Get("Upgrade") == "websocket" {
				e = wsDealer(ctx1, w, r, path, backIs, logger, configS.BlocksI)
			} else {
				e = httpDealer(ctx1, w, r, path, backIs, logger, configS.BlocksI)
			}
			if errors.Is(e, ErrHeaderCheckFail) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		})
	}
	return nil
}

var (
	ErrRedirect        = errors.New("ErrRedirect")
	ErrNoHttp          = errors.New("ErrNoHttp")
	ErrNoWs            = errors.New("ErrNoWs")
	ErrCopy            = errors.New("ErrCopy")
	ErrReqCreFail      = errors.New("ErrReqCreFail")
	ErrReqDoFail       = errors.New("ErrReqDoFail")
	ErrResDoFail       = errors.New("ErrResDoFail")
	ErrHeaderCheckFail = errors.New("ErrHeaderCheckFail")
)

func httpDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, backs []*Back, logger Logger, blocksi pslice.BlocksI[byte]) error {
	var (
		resp       *http.Response
		chosenBack *Back
	)

	for 0 < len(backs) && resp == nil {
		chosenBack = backs[nanotime1()%int64(len(backs))]
		backs = backs[1:]

		url := chosenBack.To
		if chosenBack.PathAdd {
			url += r.URL.String()
		}

		url = "http" + url

		for _, v := range chosenBack.ReqHeader {
			if v.Action == `check` {
				if r.Header.Get(v.Key) != v.Value {
					return ErrHeaderCheckFail
				}
			}
		}

		req, e := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
		if e != nil {
			return errors.Join(ErrReqCreFail, e)
		}

		if e := copyHeader(r.Header, req.Header, chosenBack.ReqHeader); e != nil {
			logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
			return e
		}

		req.Header.Del("Referer")

		client := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return ErrRedirect
			},
		}
		resp, e = client.Do(req)
		if e != nil && !errors.Is(e, ErrRedirect) {
			chosenBack.Disable()
			logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
		}
	}

	if 0 == len(backs) && resp == nil {
		logger.Warn(`E:`, fmt.Sprintf("%s=>%s 全部后端故障", routePath, chosenBack.Name))
		return errors.New("全部后端故障")
	} else if resp == nil {
		return errors.New("后端故障")
	}

	logger.Error(`T:`, fmt.Sprintf("%s=>%s", routePath, chosenBack.Name))

	if validCookieDomain(r.Host) {
		w.Header().Add("Set-Cookie", (&http.Cookie{
			Name:   "_psign_" + cookie,
			Value:  chosenBack.Sign,
			MaxAge: chosenBack.Splicing,
			Domain: r.Host,
		}).String())
	}

	w.Header().Add("_pto_"+cookie, chosenBack.Name)

	if e := copyHeader(resp.Header, w.Header(), chosenBack.ResHeader); e != nil {
		logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
		return e
	}

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}

	defer resp.Body.Close()
	if tmpbuf, put, e := blocksi.Get(); e != nil {
		logger.Error(`E:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
		chosenBack.Disable()
		return errors.Join(ErrCopy, e)
	} else {
		defer put()
		if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
			logger.Error(`E:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
			chosenBack.Disable()
			return errors.Join(ErrCopy, e)
		}
	}
	return nil
}

func wsDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, backs []*Back, logger Logger, blocksi pslice.BlocksI[byte]) error {
	var (
		resp       *http.Response
		conn       net.Conn
		chosenBack *Back
	)

	for 0 < len(backs) && (resp == nil || conn == nil) {
		chosenBack = backs[nanotime1()%int64(len(backs))]
		backs = backs[1:]

		url := chosenBack.To
		if chosenBack.PathAdd {
			url += r.URL.String()
		}

		url = "ws" + url

		reqHeader := make(http.Header)

		if e := copyHeader(r.Header, reqHeader, chosenBack.ReqHeader); e != nil {
			logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
			return e
		}

		reqHeader.Del("Referer")

		var e error
		conn, resp, e = DialContext(ctx, url, reqHeader)
		if e != nil {
			chosenBack.Disable()
			logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
		}
	}

	if 0 == len(backs) && (resp == nil || conn == nil) {
		logger.Warn(`E:`, fmt.Sprintf("%s=>%s 全部后端故障", routePath, chosenBack.Name))
		return errors.New("全部后端故障")
	} else if resp == nil || conn == nil {
		return errors.New("后端故障")
	}

	logger.Error(`T:`, fmt.Sprintf("%s=>%s", routePath, chosenBack.Name))

	if validCookieDomain(r.Host) {
		w.Header().Add("Set-Cookie", (&http.Cookie{
			Name:   "_psign_" + cookie,
			Value:  chosenBack.Sign,
			MaxAge: chosenBack.Splicing,
			Domain: r.Host,
		}).String())
	}

	w.Header().Add("_pto_"+cookie, chosenBack.Name)

	defer conn.Close()

	resHeader := make(http.Header)
	if e := copyHeader(resp.Header, resHeader, chosenBack.ResHeader); e != nil {
		logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, chosenBack.Name, e))
		return e
	}

	if req, e := Upgrade(w, r, resHeader); e != nil {
		return errors.Join(ErrResDoFail, e)
	} else {
		defer req.Close()

		select {
		case e := <-copyWsMsg(req, conn, blocksi):
			if e != nil {
				chosenBack.Disable()
				logger.Error(`E:`, fmt.Sprintf("%s=>%s s->c %v", routePath, chosenBack.Name, e))
				return errors.Join(ErrCopy, e)
			}
		case e := <-copyWsMsg(conn, req, blocksi):
			if e != nil {
				chosenBack.Disable()
				logger.Error(`E:`, fmt.Sprintf("%s=>%s c->s %v", routePath, chosenBack.Name, e))
				return errors.Join(ErrCopy, e)
			}
		case <-ctx.Done():
		}

		return nil
	}
}

func copyHeader(s, t http.Header, app []Header) error {
	sm := (map[string][]string)(s)
	tm := (map[string][]string)(t)
	for k, v := range sm {
		if strings.ToLower(k) == "set-cookie" {
			cookies := strings.Split(v[0], ";")
			for k, v := range cookies {
				if strings.Contains(strings.ToLower(v), "domain=") {
					cookies = append(cookies[:k], cookies[k+1:]...)
					break
				}
			}
			tm[k] = []string{strings.Join(cookies, ";")}
		} else {
			tm[k] = v
		}
	}
	for _, v := range app {
		switch v.Action {
		case `check`:
			if val := tm[v.Key]; val[0] != v.Value {
				return ErrHeaderCheckFail
			}
		case `set`:
			t.Set(v.Key, v.Value)
		case `add`:
			t.Add(v.Key, v.Value)
		case `del`:
			t.Del(v.Key)
		default:
		}
	}
	return nil
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

func DialContext(ctx context.Context, urlStr string, requestHeader http.Header) (net.Conn, *http.Response, error) {
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
		return nil, nil, errMalformedURL
	}

	if u.User != nil {
		// User name and password are not allowed in websocket URIs.
		return nil, nil, errMalformedURL
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
		return nil, nil, errMalformedURL
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

	hostPort, hostNoPort := hostPortNoPort(u)
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

		cfg := cloneTLSConfig(d.TLSClientConfig)
		if cfg.ServerName == "" {
			cfg.ServerName = hostNoPort
		}
		tlsConn := tls.Client(netConn, cfg)
		netConn = tlsConn

		if trace != nil && trace.TLSHandshakeStart != nil {
			trace.TLSHandshakeStart()
		}
		err := doHandshake(ctx, tlsConn, cfg)
		if trace != nil && trace.TLSHandshakeDone != nil {
			trace.TLSHandshakeDone(tlsConn.ConnectionState(), err)
		}

		if err != nil {
			return nil, nil, err
		}
	}

	var br *bufio.Reader
	if br == nil {
		if d.ReadBufferSize == 0 {
			d.ReadBufferSize = defaultReadBufferSize
		} else if d.ReadBufferSize < maxControlFramePayloadSize {
			// must be large enough for control frame
			d.ReadBufferSize = maxControlFramePayloadSize
		}
		br = bufio.NewReaderSize(netConn, d.ReadBufferSize)
	}

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
		!tokenListContainsValue(resp.Header, "Upgrade", "websocket") ||
		!tokenListContainsValue(resp.Header, "Connection", "upgrade") ||
		resp.Header.Get("Sec-Websocket-Accept") != computeAcceptKey(challengeKey) {
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

//go:linkname doHandshake github.com/gorilla/websocket.doHandshake
func doHandshake(ctx context.Context, tlsConn *tls.Conn, cfg *tls.Config) error

//go:linkname cloneTLSConfig github.com/gorilla/websocket.cloneTLSConfig
func cloneTLSConfig(cfg *tls.Config) *tls.Config

//go:linkname hostPortNoPort github.com/gorilla/websocket.hostPortNoPort
func hostPortNoPort(u *url.URL) (hostPort, hostNoPort string)

//go:linkname errMalformedURL github.com/gorilla/websocket.errMalformedURL
var errMalformedURL error

//go:linkname errInvalidCompression github.com/gorilla/websocket.errInvalidCompression
var errInvalidCompression error

//go:linkname generateChallengeKey github.com/gorilla/websocket.generateChallengeKey
func generateChallengeKey() (string, error)

//go:linkname tokenListContainsValue github.com/gorilla/websocket.tokenListContainsValue
func tokenListContainsValue(header http.Header, name string, value string) bool

//go:linkname returnError github.com/gorilla/websocket.(*Upgrader).returnError
// func returnError(u *websocket.Upgrader, w http.ResponseWriter, r *http.Request, status int, reason string) (*websocket.Conn, error)

//go:linkname checkSameOrigin github.com/gorilla/websocket.checkSameOrigin
func checkSameOrigin(r *http.Request) bool

//go:linkname isValidChallengeKey github.com/gorilla/websocket.isValidChallengeKey
func isValidChallengeKey(s string) bool

//go:linkname selectSubprotocol github.com/gorilla/websocket.(*Upgrader).selectSubprotocol
func selectSubprotocol(u *websocket.Upgrader, r *http.Request, responseHeader http.Header) string

//go:linkname parseExtensions github.com/gorilla/websocket.parseExtensions
func parseExtensions(header http.Header) []map[string]string

//go:linkname bufioReaderSize github.com/gorilla/websocket.bufioReaderSize
func bufioReaderSize(originalReader io.Reader, br *bufio.Reader) int

//go:linkname bufioWriterBuffer github.com/gorilla/websocket.bufioWriterBuffer
func bufioWriterBuffer(originalWriter io.Writer, bw *bufio.Writer) []byte

//go:linkname computeAcceptKey github.com/gorilla/websocket.computeAcceptKey
func computeAcceptKey(challengeKey string) string

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

	buf := bufioWriterBuffer(netConn, brw.Writer)

	var writeBuf []byte
	if u.WriteBufferPool == nil && u.WriteBufferSize == 0 && len(buf) >= maxFrameHeaderSize+256 {
		// Reuse hijacked write buffer as connection buffer.
		writeBuf = buf
	} else {
		if u.WriteBufferSize <= 0 {
			u.WriteBufferSize = defaultWriteBufferSize
		}
		u.WriteBufferSize += maxFrameHeaderSize
		if writeBuf == nil && u.WriteBufferPool == nil {
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
