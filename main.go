package front

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"
	_ "unsafe"

	"github.com/gorilla/websocket"
	pctx "github.com/qydysky/part/ctx"
	pweb "github.com/qydysky/part/web"
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

func applyConfig(ctx context.Context, configS *Config, routeP *pweb.WebPath, logger Logger) error {
	configS.lock.RLock()
	defer configS.lock.RUnlock()

	for i := 0; i < len(configS.Routes); i++ {
		route := &configS.Routes[i]
		path := route.Path
		splicing := route.Splicing
		ErrRedirect := route.ErrRedirect

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

			var backI *Back
			validHost := validCookieDomain(r.Host)
			if validHost {
				if t, e := r.Cookie("_psign_" + cookie); e == nil {
					if tmp, ok := backMap[t.Value]; ok {
						backI = tmp
					}
				}
			}

			if backI == nil {
				backArray := GetBackByRequest(backArray, r)
				switch len(backArray) {
				case 0:
					w.WriteHeader(http.StatusServiceUnavailable)
					logger.Error(`W:`, fmt.Sprintf("%s=> 无匹配", path))
					return
				case 1:
					backI = backArray[0]
				default:
					backI = backArray[rand.Int63()%int64(len(backArray))]
				}
				if !backI.IsLive() {
					backI = nil
					for i := 0; i < len(backArray); i++ {
						if backArray[i].IsLive() {
							backI = backArray[i]
							break
						}
					}
					if backI == nil {
						w.WriteHeader(http.StatusServiceUnavailable)
						logger.Error(`E:`, fmt.Sprintf("%s=> 全部后端失效", path))
						return
					}
				}
			}

			if validHost {
				w.Header().Add("Set-Cookie", (&http.Cookie{
					Name:   "_psign_" + cookie,
					Value:  backI.Sign,
					MaxAge: splicing,
					Path:   path,
					Domain: r.Host,
				}).String())
			}

			w.Header().Add("_pto_"+cookie, backI.Name)

			logger.Error(`T:`, fmt.Sprintf("%s=>%s", path, backI.Name))

			var e error
			if r.Header.Get("Upgrade") == "websocket" {
				e = wsDealer(ctx1, w, r, path, backI, logger)
			} else {
				e = httpDealer(ctx1, w, r, path, backI, logger)
			}
			if e != nil {
				logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", path, backI.Name, e))
				switch e {
				case ErrCopy:
					backI.Disable()
					return
				case ErrHeaderCheckFail:
					w.WriteHeader(http.StatusForbidden)
					return
				default:
					backI.Disable()
					if ErrRedirect {
						w.Header().Set("Location", r.URL.String())
						w.WriteHeader(http.StatusTemporaryRedirect)
					}
				}
			}
		})
	}
	return nil
}

var (
	ErrNoHttp          = errors.New("ErrNoHttp")
	ErrNoWs            = errors.New("ErrNoWs")
	ErrCopy            = errors.New("ErrCopy")
	ErrReqCreFail      = errors.New("ErrReqCreFail")
	ErrReqDoFail       = errors.New("ErrReqDoFail")
	ErrResDoFail       = errors.New("ErrResDoFail")
	ErrHeaderCheckFail = errors.New("ErrHeaderCheckFail")
)

func httpDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, back *Back, logger Logger) error {
	url := back.To
	if back.PathAdd {
		url += r.URL.String()
	}

	url = "http" + url

	for _, v := range back.ReqHeader {
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

	if e := copyHeader(r.Header, req.Header, back.ReqHeader); e != nil {
		logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return e
	}

	client := http.Client{}
	resp, e := client.Do(req)
	if e != nil {
		return errors.Join(ErrReqDoFail, e)
	}

	if e := copyHeader(resp.Header, w.Header(), back.ResHeader); e != nil {
		logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return e
	}

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}

	defer resp.Body.Close()
	if _, e = io.Copy(w, resp.Body); e != nil {
		logger.Error(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return errors.Join(ErrCopy, e)
	}
	return nil
}

func wsDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, back *Back, logger Logger) error {
	url := back.To
	if back.PathAdd {
		url += r.URL.String()
	}

	url = "ws" + url

	tmpHeader := make(http.Header)

	dialer := websocket.DefaultDialer

	if strings.Contains(r.Header.Get("Sec-Websocket-Extensions"), "permessage-deflate") {
		dialer.EnableCompression = true
	}

	if e := copyHeader(r.Header, tmpHeader, back.ReqHeader, delWsHeaders); e != nil {
		logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return e
	}

	jar, _ := cookiejar.New(nil)
	jar.SetCookies(r.URL, r.Cookies())

	dialer.Jar = jar

	if res, resp, e := dialer.Dial(url, tmpHeader); e != nil {
		return errors.Join(ErrReqDoFail, e)
	} else {
		defer res.Close()

		clear(tmpHeader)
		if e := copyHeader(resp.Header, tmpHeader, back.ResHeader, delWsHeaders); e != nil {
			logger.Warn(`W:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
			return e
		}

		if req, e := (&websocket.Upgrader{}).Upgrade(w, r, tmpHeader); e != nil {
			return errors.Join(ErrResDoFail, e)
		} else {
			defer req.Close()

			fin := make(chan error, 2)
			reqc := req.NetConn()
			resc := res.NetConn()
			go func() {
				ctx1, done1 := pctx.WaitCtx(ctx)
				defer done1()
				select {
				case fin <- copyWsMsg(reqc, resc):
				case <-ctx1.Done():
					fin <- nil
				}
			}()
			go func() {
				ctx1, done1 := pctx.WaitCtx(ctx)
				defer done1()
				select {
				case fin <- copyWsMsg(resc, reqc):
				case <-ctx1.Done():
					fin <- nil
				}
			}()
			if e := <-fin; e != nil {
				logger.Error(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
				return errors.Join(ErrCopy, e)
			}
			return nil
		}
	}
}

var delWsHeaders = map[string]*any{
	`Connection`:               nil,
	`Upgrade`:                  nil,
	`Sec-Websocket-Accept`:     nil,
	`Sec-Websocket-Key`:        nil,
	`Sec-Websocket-Version`:    nil,
	`Sec-Websocket-Protocol`:   nil,
	`Sec-Websocket-Extensions`: nil,
}

func copyHeader(s, t http.Header, app []Header, delHeader ...map[string]*any) error {
	sm := (map[string][]string)(s)
	tm := (map[string][]string)(t)
	for k, v := range sm {
		if _, ok := delWsHeaders[k]; ok {
			continue
		}
		tm[k] = v
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

func copyWsMsg(dst io.Writer, src io.Reader) (e error) {
	_, e = io.Copy(dst, src)
	return
}
