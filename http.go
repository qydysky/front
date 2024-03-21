package front

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
	_ "unsafe"

	pslice "github.com/qydysky/part/slice"
)

func httpDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, backs []*Back, logger Logger, blocksi pslice.BlocksI[byte]) error {

	var (
		opT        = time.Now()
		resp       *http.Response
		chosenBack *Back
		logFormat  = "%v%v > %v http %v %v %v"
	)

	for 0 < len(backs) && resp == nil {
		chosenBack = backs[0]
		backs = backs[1:]

		if !chosenBack.IsLive() {
			continue
		}

		url := chosenBack.To
		if chosenBack.PathAdd() {
			url += r.RequestURI
		}

		url = "http" + url

		req, e := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
		if e != nil {
			return ErrReqCreFail
		}

		if e := copyHeader(r.Header, req.Header, chosenBack.Setting.Dealer.ReqHeader); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
			return ErrDealReqHeader
		}

		client := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return ErrRedirect
			},
		}
		resp, e = client.Do(req)
		if e != nil && !errors.Is(e, ErrRedirect) && !errors.Is(e, context.Canceled) {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
			chosenBack.Disable()
			resp = nil
		}

		if chosenBack.getErrToSec() != 0 && time.Since(opT).Seconds() > chosenBack.getErrToSec() {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", ErrResTO, time.Since(opT)))
			chosenBack.Disable()
			resp = nil
		}
	}

	if resp == nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", ErrAllBacksFail, time.Since(opT)))
		return ErrAllBacksFail
	}

	if ok, e := chosenBack.getFiliterResHeader().Match(resp.Header); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
	} else if !ok {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", ErrHeaderCheckFail, time.Since(opT)))
		w.Header().Add(header+"Error", ErrHeaderCheckFail.Error())
		w.WriteHeader(http.StatusForbidden)
		return ErrHeaderCheckFail
	}

	logger.Debug(`T:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, r.Method, r.RequestURI, time.Since(opT)))

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
		if validCookieDomain(r.Host) {
			cookie.Domain = r.Host
		}
		w.Header().Add("Set-Cookie", (cookie).String())
	}

	w.Header().Add(header+"Info", cookie+";"+chosenBack.Name)

	if e := copyHeader(resp.Header, w.Header(), chosenBack.Setting.Dealer.ResHeader); e != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
		return ErrDealResHeader
	}

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}

	defer resp.Body.Close()
	if tmpbuf, put, e := blocksi.Get(); e != nil {
		logger.Error(`E:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
		chosenBack.Disable()
		return ErrCopy
	} else {
		defer put()
		if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
			logger.Error(`E:`, fmt.Sprintf(logFormat, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
			if !errors.Is(e, context.Canceled) {
				chosenBack.Disable()
			}
			return ErrCopy
		}
	}
	return nil
}
