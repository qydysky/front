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
	)

	for 0 < len(backs) && resp == nil {
		chosenBack = backs[0]
		backs = backs[1:]

		if !chosenBack.IsLive() {
			continue
		}

		url := chosenBack.To
		if chosenBack.PathAdd {
			url += r.URL.RequestURI()
		}

		url = "http" + url

		reader, e := BodyMatchs(chosenBack.tmp.ReqBody, r)
		if e != nil {
			logger.Warn(`W:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
			return errors.Join(ErrBodyCheckFail, e)
		}

		req, e := http.NewRequestWithContext(ctx, r.Method, url, reader)
		if e != nil {
			return errors.Join(ErrReqCreFail, e)
		}

		if e := copyHeader(r.Header, req.Header, chosenBack.tmp.ReqHeader); e != nil {
			logger.Warn(`W:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
			return e
		}

		client := http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return ErrRedirect
			},
		}
		resp, e = client.Do(req)
		if e != nil && !errors.Is(e, ErrRedirect) && !errors.Is(e, context.Canceled) {
			chosenBack.Disable()
			logger.Warn(`W:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
		}
	}

	if resp == nil {
		logger.Warn(`W:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, ErrAllBacksFail, time.Since(opT)))
		return ErrAllBacksFail
	}

	if chosenBack.ErrToSec != 0 && time.Since(opT).Seconds() > chosenBack.ErrToSec {
		logger.Warn(`W:`, fmt.Sprintf("%v > %v > %v http 超时响应 %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, time.Since(opT)))
		chosenBack.Disable()
	} else {
		logger.Debug(`T:`, fmt.Sprintf("%v > %v > %v http ok %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, time.Since(opT)))
	}

	{
		cookie := &http.Cookie{
			Name:   "_psign_" + cookie,
			Value:  chosenBack.Id(),
			MaxAge: chosenBack.Splicing,
			Path:   "/",
		}
		if validCookieDomain(r.Host) {
			cookie.Domain = r.Host
		}
		w.Header().Add("Set-Cookie", (cookie).String())
	}

	w.Header().Add(header+"Info", cookie+";"+chosenBack.Name)

	if e := copyHeader(resp.Header, w.Header(), chosenBack.tmp.ResHeader); e != nil {
		logger.Warn(`W:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
		return e
	}

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}

	defer resp.Body.Close()
	if tmpbuf, put, e := blocksi.Get(); e != nil {
		logger.Error(`E:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
		chosenBack.Disable()
		return errors.Join(ErrCopy, e)
	} else {
		defer put()
		if _, e = io.CopyBuffer(w, resp.Body, tmpbuf); e != nil {
			logger.Error(`E:`, fmt.Sprintf("%v > %v > %v http %v %v", chosenBack.route.config.Addr, routePath, chosenBack.Name, e, time.Since(opT)))
			chosenBack.Disable()
			return errors.Join(ErrCopy, e)
		}
	}
	return nil
}
