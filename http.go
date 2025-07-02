package front

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	netUrl "net/url"
	"strings"
	"time"
	_ "unsafe"

	"compress/flate"
	gzip "compress/gzip"

	br "github.com/qydysky/brotli"
	"github.com/qydysky/front/utils"
	component2 "github.com/qydysky/part/component2"
	pctx "github.com/qydysky/part/ctx"
	pio "github.com/qydysky/part/io"
	pslice "github.com/qydysky/part/slice"
)

func init() {
	type I interface {
		Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error
	}
	if e := component2.Register[I]("http", httpDealer{}); e != nil {
		panic(e)
	}
}

type httpDealer struct{}

func (httpDealer) Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error {
	var (
		opT       = time.Now()
		resp      *http.Response
		logFormat = "%v %v %v%v > %v http %v %v %v"
	)

	url := chosenBack.To
	if chosenBack.getPathAdd() {
		url += r.RequestURI
	}

	url = "http" + url

	url = dealUri(url, chosenBack.getDealerReqUri())

	req, e := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
	if e != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
		chosenBack.Disable()
		return MarkRetry(ErrReqCreFail)
	}

	// if e :=
	copyHeader(r.Header, req.Header, chosenBack.getDealerReqHeader())
	// ; e != nil {
	// 	logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
	// 	return ErrDealReqHeader
	// }

	customTransport := http.DefaultTransport.(*http.Transport).Clone()

	customTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: chosenBack.getInsecureSkipVerify(),
	}

	if chosenBack.getProxy() != "" {
		customTransport.Proxy = func(_ *http.Request) (*netUrl.URL, error) {
			return netUrl.Parse(chosenBack.getProxy())
		}
	}

	if cer, err := chosenBack.getVerifyPeerCer(); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(cer) {
			customTransport.TLSClientConfig.InsecureSkipVerify = true
			customTransport.TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) (e error) {
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
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", ErrCerVerify, time.Since(opT)))
		}
	} else if err != ErrEmptyVerifyPeerCerByte {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", err, time.Since(opT)))
	}

	client := http.Client{
		Transport: customTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return ErrRedirect
		},
	}

	resp, e = client.Do(req)
	if e != nil && !errors.Is(e, ErrRedirect) && !errors.Is(e, context.Canceled) {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
		chosenBack.Disable()
		return MarkRetry(ErrResFail)
	}

	if chosenBack.getErrToSec() != 0 && time.Since(opT).Seconds() > chosenBack.getErrToSec() {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", ErrResTO, time.Since(opT)))
		chosenBack.Disable()
	}

	if pctx.Done(r.Context()) {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", context.Canceled, time.Since(opT)))
		return context.Canceled
	}

	if resp == nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
		return MarkRetry(ErrResFail)
	}

	var noPassFiliter bool
	for filiter := range chosenBack.getFiliters() {
		noPassFiliter = true
		if ok, e := filiter.ResHeader.Match(resp.Header); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
		} else if !ok {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", ErrHeaderCheckFail, time.Since(opT)))
			continue
		}
		noPassFiliter = false
		break
	}
	if noPassFiliter {
		w.Header().Add(header+"Error", ErrHeaderCheckFail.Error())
		return MarkRetry(ErrHeaderCheckFail)
	}

	logger.Debug(`T:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, r.Method, r.RequestURI, time.Since(opT)))

	if chosenBack.route.RollRule != `` {
		chosenBack.be(opT)
		defer chosenBack.ed()
	}

	if chosenBack.getSplicing() != 0 {
		cookie := &http.Cookie{
			Name:   cookie,
			Value:  chosenBack.Id(),
			MaxAge: chosenBack.getSplicing(),
			Path:   routePath,
		}
		if utils.ValidCookieDomain(r.Host) {
			cookie.Domain = r.Host
		}
		w.Header().Add("Set-Cookie", (cookie).String())
	}

	w.Header().Add(header+"Info", chosenBack.Name)

	// if e :=
	copyHeader(resp.Header, w.Header(), chosenBack.getDealerResHeader())
	// ; e != nil {
	// 	logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
	// 	return ErrDealResHeader
	// }

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 ||
		resp.StatusCode == http.StatusNoContent ||
		(resp.StatusCode < 400 && resp.StatusCode >= 300) {
		return nil
	}

	defer resp.Body.Close()
	if tmpbuf, put, e := blocksi.Get(); e != nil {
		logger.Error(`E:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
		chosenBack.Disable()
		return ErrCopy
	} else {
		defer put()

		var dealers []func(data []byte) (dealed []byte, stop bool)
		for _, v := range chosenBack.getDealerResBody() {
			switch v.Action {
			case `replace`:
				dealers = append(dealers, v.GetReplaceDealer())
			default:
			}
		}
		if len(dealers) > 0 {
			var reader io.Reader
			var writer io.Writer
			var dealBody bool
			switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
			case `br`:
				reader = br.NewReader(resp.Body)
				w1 := br.NewWriter(w)
				writer = pio.RWC{
					W: func(p []byte) (n int, err error) {
						n, err = w1.Write(p)
						w1.Flush()
						return
					},
				}
				dealBody = true
			case `gzip`:
				if tmp, e := gzip.NewReader(resp.Body); e != nil {
					logger.Error(`E:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
					return ErrCopy
				} else {
					reader = tmp
					w1 := gzip.NewWriter(w)
					writer = pio.RWC{
						W: func(p []byte) (n int, err error) {
							n, err = w1.Write(p)
							w1.Flush()
							return
						},
					}
				}
				dealBody = true
			case `deflate`:
				if tmp, e := flate.NewWriter(w, 1); e != nil {
					logger.Error(`E:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
					return ErrCopy
				} else {
					reader = flate.NewReader(resp.Body)
					writer = pio.RWC{
						W: func(p []byte) (n int, err error) {
							n, err = tmp.Write(p)
							tmp.Flush()
							return
						},
					}
				}
				dealBody = true
			case ``:
				reader = resp.Body
				writer = w
				dealBody = true
			default:
				reader = resp.Body
				writer = w
			}
			if dealBody {
				if e := pio.CopyDealer(writer, reader, tmpbuf, dealers...); e != nil {
					logger.Error(`E:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
					return ErrCopy
				}
			} else if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
				logger.Error(`E:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
				if !errors.Is(e, context.Canceled) {
					chosenBack.Disable()
				}
				return ErrCopy
			}
		} else if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
			logger.Error(`E:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
			if !errors.Is(e, context.Canceled) {
				chosenBack.Disable()
			}
			return ErrCopy
		}
	}
	return nil
}
