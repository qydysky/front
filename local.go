package front

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
	_ "unsafe"

	"github.com/qydysky/front/utils"
	component2 "github.com/qydysky/part/component2"
	pfile "github.com/qydysky/part/file"
	pslice "github.com/qydysky/part/slice"
)

func init() {
	type I interface {
		Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error
	}
	if e := component2.Register[I]("local", localDealer{}); e != nil {
		panic(e)
	}
}

type localDealer struct{}

func (localDealer) Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error {
	var (
		opT       = time.Now()
		logFormat = "%v %v %v%v > %v local %v %v %v"
	)

	path := chosenBack.To
	if chosenBack.getPathAdd() {
		if s, e := url.PathUnescape(r.URL.Path); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "Err", e, time.Since(opT)))
			return ErrDealReqUri
		} else {
			path += s
		}
	}

	if !pfile.New(path, 0, true).IsExist() {
		return MarkRetry(os.ErrNotExist)
	}

	logger.Debug(`T:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, r.Method, r.RequestURI, time.Since(opT)))

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
	copyHeader(http.Header{}, w.Header(), chosenBack.getDealerResHeader())
	// ; e != nil {
	// 	logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.Name, "BLOCK", e, time.Since(opT)))
	// 	return ErrDealResHeader
	// }

	http.ServeFile(w, r.WithContext(ctx), path)
	return nil
}
