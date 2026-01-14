package front

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	netUrl "net/url"
	"regexp"
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
	plog "github.com/qydysky/part/log/v2"
	pool "github.com/qydysky/part/pool"
)

func init() {
	type I interface {
		Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger *plog.Log, blocksi pool.BlocksI[byte]) error
	}
	if e := component2.Register[I]("http", httpDealer{}); e != nil {
		panic(e)
	}
}

type httpDealer struct{}

var clientPool = pool.New(pool.PoolFunc[http.Client]{
	New: func() *http.Client {
		return &http.Client{
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return ErrRedirect
			},
		}
	},
}, -1)

func (httpDealer) Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger *plog.Log, blocksi pool.BlocksI[byte]) error {
	var (
		env       = make(map[string]string)
		opT       = time.Now()
		resp      *http.Response
		logFormat = "%v %v %v%v > %v > %v http %v %v %v"
	)

	// for v := range chosenBack.getDealerReqFunc() {
	// 	v.Dealer(r)
	// }

	url := chosenBack.To
	if chosenBack.getPathAdd() {
		url += r.RequestURI
	}

	url = "http" + url

	url = dealUri(url, chosenBack.getDealerReqUri())

	req, e := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
	if e != nil {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
		chosenBack.Disable()
		return MarkRetry(ErrReqCreFail)
	}

	setEnvIfNot(env, `$remote_addr`, r.Header.Get("X-Real-IP"))
	setEnvIfNot(env, `$remote_addr`, strings.Split(r.RemoteAddr, ":")[0])

	copyHeader(env, r.Header, req.Header, chosenBack.getDealerReqHeader())

	client := clientPool.Get()
	defer clientPool.Put(client)

	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: chosenBack.getInsecureSkipVerify(),
	}

	if chosenBack.getProxy() != "" {
		client.Transport.(*http.Transport).Proxy = func(_ *http.Request) (*netUrl.URL, error) {
			return netUrl.Parse(chosenBack.getProxy())
		}
	}

	if cer, err := chosenBack.getVerifyPeerCer(); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(cer) {
			client.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
			client.Transport.(*http.Transport).TLSClientConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) (e error) {
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
			logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, ErrCerVerify, time.Since(opT))
		}
	} else if err != ErrEmptyVerifyPeerCerByte {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, err, time.Since(opT))
	}

	resp, e = client.Do(req)

	// for v := range chosenBack.getDealerResFunc() {
	// 	v.Dealer(req, resp)
	// }

	if e != nil && !errors.Is(e, ErrRedirect) && !errors.Is(e, context.Canceled) && !errors.Is(e, context.DeadlineExceeded) {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
		chosenBack.Disable()
		return MarkRetry(ErrResFail)
	}

	if chosenBack.getErrToSec() != 0 && time.Since(opT).Seconds() > chosenBack.getErrToSec() {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, ErrResTO, time.Since(opT))
		chosenBack.Disable()
	}

	if pctx.Done(ctx) {
		w.WriteHeader(http.StatusGatewayTimeout)
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, context.DeadlineExceeded, time.Since(opT))
		chosenBack.Disable()
		return context.DeadlineExceeded
	}

	if pctx.Done(r.Context()) {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, context.Canceled, time.Since(opT))
		return context.Canceled
	}

	if resp == nil {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
		return MarkRetry(ErrResFail)
	}

	var filiterErr error
	for filiter := range chosenBack.getFiliters() {
		filiterErr = nil
		if ok, e := filiter.ResHeader.Match(resp.Header); e != nil {
			logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
		} else if !ok {
			filiterErr = ErrHeaderCheckFail
			continue
		}
		if filiter.ResFunc.Filiter != nil && !filiter.ResFunc.Filiter(r, resp) {
			filiterErr = ErrFuncCheckFail
			continue
		}
		break
	}
	if filiterErr != nil {
		logger.WF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, filiterErr, time.Since(opT))
		return MarkRetry(filiterErr)
	}

	logger.TF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.Method, r.RequestURI, time.Since(opT))

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

	// w.Header().Add(header+"Info", chosenBack.Name)

	copyHeader(env, resp.Header, w.Header(), chosenBack.getDealerResHeader())

	for v := range chosenBack.getDealerResStatus(func() { w.WriteHeader(resp.StatusCode) }) {
		if regexp.MustCompile(v.MatchExp).MatchString(resp.Status) {
			w.WriteHeader(v.Value)
			break
		}
	}

	if resp.StatusCode < 200 ||
		resp.StatusCode == http.StatusNoContent ||
		(resp.StatusCode < 400 && resp.StatusCode >= 300) {
		return nil
	}

	defer resp.Body.Close()
	if tmpbuf, put, e := blocksi.Get(); e != nil {
		logger.EF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
		chosenBack.Disable()
		return errors.Join(ErrCopy, e)
	} else {
		defer put()

		var dealers []func(data []byte) (dealed []byte, stop bool)
		for v := range chosenBack.getDealerResBody() {
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
					logger.EF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
					return errors.Join(ErrCopy, e)
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
					logger.EF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
					return errors.Join(ErrCopy, e)
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
					logger.EF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
					return errors.Join(ErrCopy, e)
				}
			} else if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
				logger.EF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
				if !errors.Is(e, context.Canceled) {
					chosenBack.Disable()
				}
				return errors.Join(ErrCopy, e)
			}
		} else if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
			logger.EF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.RequestURI, e, time.Since(opT))
			if !errors.Is(e, context.Canceled) {
				chosenBack.Disable()
			}
			return errors.Join(ErrCopy, e)
		}
	}
	return nil
}
