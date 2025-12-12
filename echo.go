package front

import (
	"context"
	"net/http"
	"strings"
	"time"
	_ "unsafe"

	"github.com/qydysky/front/utils"
	component2 "github.com/qydysky/part/component2"
	plog "github.com/qydysky/part/log/v2"
	pool "github.com/qydysky/part/pool"
)

func init() {
	type I interface {
		Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger *plog.Log, blocksi pool.BlocksI[byte]) error
	}
	if e := component2.Register[I]("echo", echoDealer{}); e != nil {
		panic(e)
	}
}

type echoDealer struct{}

func (echoDealer) Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger *plog.Log, blocksi pool.BlocksI[byte]) error {
	var (
		env       = make(map[string]string)
		opT       = time.Now()
		logFormat = "%v %v %v%v > %v > %v echo %v %v %v"
	)

	logger.TF(logFormat, reqId, r.RemoteAddr, chosenBack.route.config.Addr, routePath, chosenBack.route.Name, chosenBack.Name, r.Method, r.RequestURI, time.Since(opT))

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

	setEnvIfNot(env, `$remote_addr`, r.Header.Get("X-Real-IP"))
	setEnvIfNot(env, `$remote_addr`, strings.Split(r.RemoteAddr, ":")[0])

	copyHeader(env, http.Header{}, w.Header(), chosenBack.getDealerResHeader())

	for v := range chosenBack.getDealerResStatus(func() { w.WriteHeader(http.StatusOK) }) {
		w.WriteHeader(v.Value)
		break
	}

	return nil
}
