package front

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	pctx "github.com/qydysky/part/ctx"
	pfile "github.com/qydysky/part/file"
	plog "github.com/qydysky/part/log"
	pweb "github.com/qydysky/part/web"
)

// 加载
func LoadPeriod(ctx context.Context, buf []byte, configF *pfile.File, configS *Config, logger *plog.Log_interface) {
	if e := loadConfig(buf, configF, configS, logger); e != nil {
		logger.L(`E:`, "配置加载", e)
	}
	// 定时加载config
	go func() {
		ctx1, done1 := pctx.WaitCtx(ctx)
		defer done1()
		for {
			select {
			case <-time.After(time.Second * 10):
				if e := loadConfig(buf, configF, configS, logger); e != nil {
					logger.L(`E:`, "配置加载", e)
				}
			case <-ctx1.Done():
				return
			}
		}
	}()
}

// 测试
func Test(ctx context.Context, port int, logger *plog.Log_interface) {
	if port == 0 {
		return
	}
	logger = logger.Base("测试")
	ctx1, done1 := pctx.WaitCtx(ctx)
	defer done1()
	logger.L(`I:`, "启动", fmt.Sprintf("127.0.0.1:%d", port))
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

// 转发
func Run(ctx context.Context, configSP *Config, logger *plog.Log_interface) {
	logger = logger.Base("转发")
	// 根ctx
	ctx, cancle := pctx.WithWait(ctx, 0, time.Minute)
	defer func() {
		if errors.Is(cancle(), pctx.ErrWaitTo) {
			logger.L(`E:`, "退出超时")
		}
	}()

	// 路由
	routeP := pweb.WebPath{}

	logger.L(`I:`, "启动...")
	defer logger.L(`I:`, "退出...")

	// config对象初次加载
	if e := applyConfig(ctx, configSP, &routeP, logger); e != nil {
		return
	}

	// matchfunc
	var matchfunc func(path string) (func(w http.ResponseWriter, r *http.Request), bool)
	switch configSP.MatchRule {
	case "prefix":
		logger.L(`I:`, "匹配规则", "prefix")
		matchfunc = routeP.LoadPerfix
	case "all":
		logger.L(`I:`, "匹配规则", "all")
		matchfunc = routeP.Load
	default:
		logger.L(`E:`, "匹配规则", "无效")
		return
	}

	syncWeb := pweb.NewSyncMap(&http.Server{
		Addr: configSP.Addr,
	}, &routeP, matchfunc)
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

func loadConfig(buf []byte, configF *pfile.File, configS *Config, logger *plog.Log_interface) error {
	if i, e := configF.Read(buf); e != nil && !errors.Is(e, io.EOF) {
		logger.L(`E:`, `读取配置`, e)
		return e
	} else if i == cap(buf) {
		logger.L(`E:`, `读取配置`, `buf full`)
		return errors.New(`buf full`)
	} else {
		configS.lock.Lock()
		defer configS.lock.Unlock()
		if e := json.Unmarshal(buf[:i], configS); e != nil {
			logger.L(`E:`, `读取配置`, e)
			return e
		}
	}
	return nil
}

func applyConfig(ctx context.Context, configS *Config, routeP *pweb.WebPath, logger *plog.Log_interface) error {
	configS.lock.RLock()
	defer configS.lock.RUnlock()

	for i := 0; i < len(configS.Routes); i++ {
		route := &configS.Routes[i]
		path := route.Path

		if !route.SwapSign() {
			continue
		}

		if len(route.Back) == 0 {
			logger.L(`I:`, "移除路由", path)
			routeP.Store(path, nil)
			continue
		}

		backArray := route.GenBack()

		if len(backArray) == 0 {
			logger.L(`I:`, "移除路由", path)
			routeP.Store(path, nil)
			continue
		}

		logger.L(`I:`, "路由更新", path)

		routeP.Store(path, func(w http.ResponseWriter, r *http.Request) {
			ctx1, done1 := pctx.WaitCtx(ctx)
			defer done1()

			now := time.Now()
			backI := now.UnixMilli() % int64(len(backArray))

			if !backArray[backI].IsLive() {
				for backI = 0; backI < int64(len(backArray)); backI++ {
					if backArray[backI].IsLive() {
						break
					}
				}
				if backI == int64(len(backArray)) {
					pweb.WithStatusCode(w, http.StatusServiceUnavailable)
					logger.L(`E:`, fmt.Sprintf("%s=> 全部后端失效", path))
					return
				}
			}

			logger.L(`T:`, fmt.Sprintf("%s=>%s", path, backArray[backI].Name))

			var e error
			if r.Header.Get("Upgrade") == "websocket" {
				e = wsDealer(ctx1, w, r, path, backArray[backI], logger)
			} else {
				e = httpDealer(ctx1, w, r, path, backArray[backI], logger)
			}
			if e != nil && backArray[backI].IsLive() {
				logger.L(`W:`, fmt.Sprintf("%s=>%s 后端失效", path, backArray[backI].Name))
				backArray[backI].Disable()
			}
		})
	}
	return nil
}

var (
	ErrNoHttp     = errors.New("ErrNoHttp")
	ErrNoWs       = errors.New("ErrNoWs")
	ErrCopy       = errors.New("ErrCopy")
	ErrReqCreFail = errors.New("ErrReqCreFail")
	ErrReqDoFail  = errors.New("ErrReqDoFail")
	ErrResDoFail  = errors.New("ErrResDoFail")
)

func httpDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, back *Back, logger *plog.Log_interface) error {
	url := back.To
	if back.PathAdd {
		url += r.URL.String()
	}

	if !strings.HasPrefix(url, "http") {
		pweb.WithStatusCode(w, http.StatusServiceUnavailable)
		logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, "非http"))
		return ErrNoHttp
	}

	req, e := http.NewRequestWithContext(ctx, r.Method, url, r.Body)
	if e != nil {
		pweb.WithStatusCode(w, http.StatusServiceUnavailable)
		logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return ErrReqCreFail
	}

	for k, v := range r.Header {
		req.Header.Set(k, v[0])
	}

	for _, v := range back.ReqHeader {
		switch v.Action {
		case `set`:
			req.Header.Set(v.Key, v.Value)
		case `add`:
			req.Header.Add(v.Key, v.Value)
		case `del`:
			req.Header.Del(v.Key)
		default:
			logger.L(`W:`, fmt.Sprintf("%s=>%s 无效ReqHeader %v", routePath, back.Name, v))
		}
	}
	client := http.Client{}
	resp, e := client.Do(req)
	if e != nil {
		pweb.WithStatusCode(w, http.StatusServiceUnavailable)
		logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return ErrReqDoFail
	}

	for k, v := range resp.Header {
		w.Header().Set(k, v[0])
	}

	for _, v := range back.ResHeader {
		switch v.Action {
		case `set`:
			w.Header().Set(v.Key, v.Value)
		case `add`:
			w.Header().Add(v.Key, v.Value)
		case `del`:
			w.Header().Del(v.Key)
		default:
			logger.L(`W:`, fmt.Sprintf("%s=>%s 无效ResHeader %v", routePath, back.Name, v))
		}
	}

	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode < 200 || resp.StatusCode == 204 || resp.StatusCode == 304 {
		return nil
	}

	defer resp.Body.Close()
	if _, e = io.Copy(w, resp.Body); e != nil {
		logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return ErrCopy
	}
	return nil
}

func wsDealer(ctx context.Context, w http.ResponseWriter, r *http.Request, routePath string, back *Back, logger *plog.Log_interface) error {
	url := back.To
	if back.PathAdd {
		url += r.URL.String()
	}

	if !strings.HasPrefix(url, "ws") {
		pweb.WithStatusCode(w, http.StatusServiceUnavailable)
		logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, "非websocket"))
		return ErrNoWs
	}

	reqHeader := make(http.Header)
	for _, v := range back.ReqHeader {
		switch v.Action {
		case `set`:
			reqHeader.Set(v.Key, v.Value)
		case `add`:
			reqHeader.Add(v.Key, v.Value)
		case `del`:
			reqHeader.Del(v.Key)
		default:
			logger.L(`W:`, fmt.Sprintf("%s=>%s 无效ReqHeader %v", routePath, back.Name, v))
		}
	}
	if res, resp, e := websocket.DefaultDialer.Dial(url, reqHeader); e != nil {
		pweb.WithStatusCode(w, http.StatusServiceUnavailable)
		logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
		return ErrReqDoFail
	} else {
		for _, v := range back.ResHeader {
			switch v.Action {
			case `set`:
				resp.Header.Set(v.Key, v.Value)
			case `add`:
				resp.Header.Add(v.Key, v.Value)
			case `del`:
				resp.Header.Del(v.Key)
			default:
				logger.L(`W:`, fmt.Sprintf("%s=>%s 无效ResHeader %v", routePath, back.Name, v))
			}
		}

		if req, e := (&websocket.Upgrader{}).Upgrade(w, r, resp.Header); e != nil {
			pweb.WithStatusCode(w, http.StatusServiceUnavailable)
			logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
			return ErrResDoFail
		} else {
			fin := make(chan error)
			reqc := req.NetConn()
			resc := res.NetConn()
			defer func() {
				reqc.Close()
				resc.Close()
			}()
			go func() {
				_, e := io.Copy(reqc, resc)
				fin <- e
			}()
			go func() {
				_, e := io.Copy(resc, reqc)
				fin <- e
			}()
			select {
			case e := <-fin:
				if e != nil {
					logger.L(`E:`, fmt.Sprintf("%s=>%s %v", routePath, back.Name, e))
					return ErrCopy
				}
			case <-ctx.Done():
			}
			return nil
		}
	}
}
