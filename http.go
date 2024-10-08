package front

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	_ "unsafe"

	"github.com/qydysky/front/utils"
	component2 "github.com/qydysky/part/component2"
	pslice "github.com/qydysky/part/slice"
)

func init() {
	type I interface {
		Deal(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error
	}
	if e := component2.Register[I]("http", httpDealer{}); e != nil {
		panic(e)
	}
}

type httpDealer struct{}

func (httpDealer) Deal(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error {
	var (
		opT       = time.Now()
		resp      *http.Response
		logFormat = "%v %v%v > %v http %v %v %v"
	)

	url := chosenBack.To
	if chosenBack.PathAdd() {
		url += r.RequestURI
	}

	url = "http" + url

	url = dealUri(url, chosenBack.getDealerReqUri())

	req, e := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
	if e != nil {
		return ErrReqCreFail
	}

	if e := copyHeader(r.Header, req.Header, chosenBack.getDealerReqHeader()); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
		return ErrDealReqHeader
	}

	customTransport := http.DefaultTransport.(*http.Transport).Clone()

	customTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: chosenBack.getInsecureSkipVerify(),
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
			logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", ErrCerVerify, time.Since(opT)))
		}
	} else if err != ErrEmptyVerifyPeerCerByte {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", err, time.Since(opT)))
	}

	client := http.Client{
		Transport: customTransport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return ErrRedirect
		},
	}

	resp, e = client.Do(req)
	if e != nil && !errors.Is(e, ErrRedirect) && !errors.Is(e, context.Canceled) {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
		chosenBack.Disable()
		resp = nil
	}

	if chosenBack.getErrToSec() != 0 && time.Since(opT).Seconds() > chosenBack.getErrToSec() {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", ErrResTO, time.Since(opT)))
		chosenBack.Disable()
		resp = nil
	}

	if chosenBack == nil {
		return ErrAllBacksFail
	}

	if resp == nil {
		return ErrResFail
	}

	if ok, e := chosenBack.getFiliterResHeader().Match(resp.Header); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
	} else if !ok {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", ErrHeaderCheckFail, time.Since(opT)))
		w.Header().Add(header+"Error", ErrHeaderCheckFail.Error())
		return ErrHeaderCheckFail
	}

	logger.Debug(`T:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, r.Method, r.RequestURI, time.Since(opT)))

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

	if e := copyHeader(resp.Header, w.Header(), chosenBack.getDealerResHeader()); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
		return ErrDealResHeader
	}

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}

	defer resp.Body.Close()
	if tmpbuf, put, e := blocksi.Get(); e != nil {
		logger.Error(`E:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
		chosenBack.Disable()
		return ErrCopy
	} else {
		defer put()
		if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
			logger.Error(`E:`, fmt.Sprintf(logFormat, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
			if !errors.Is(e, context.Canceled) {
				chosenBack.Disable()
			}
			return ErrCopy
		}
	}
	return nil
}
