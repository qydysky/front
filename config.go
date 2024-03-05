package front

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"regexp"
	"sync"
	"time"

	pctx "github.com/qydysky/part/ctx"
	pslice "github.com/qydysky/part/slice"
	pweb "github.com/qydysky/part/web"
)

type Config struct {
	lock sync.RWMutex `json:"-"`
	Addr string       `json:"addr"`
	TLS  struct {
		Pub string `json:"pub"`
		Key string `json:"key"`
	} `json:"tls"`
	MatchRule  string               `json:"matchRule"`
	CopyBlocks int                  `json:"copyBlocks"`
	BlocksI    pslice.BlocksI[byte] `json:"-"`
	oldRoutes  []*Route             `json:"-"`
	Routes     []Route              `json:"routes"`
}

func (t *Config) Run(ctx context.Context, logger Logger) {
	ctx, done := pctx.WithWait(ctx, 0, time.Minute)
	defer done()

	routeP := pweb.WebPath{}

	var matchfunc func(path string) (func(w http.ResponseWriter, r *http.Request), bool)
	switch t.MatchRule {
	case "all":
		matchfunc = routeP.Load
	default:
		matchfunc = routeP.LoadPerfix
	}

	httpSer := http.Server{Addr: t.Addr}
	if t.TLS.Key != "" && t.TLS.Pub != "" {
		if cert, e := tls.LoadX509KeyPair(t.TLS.Pub, t.TLS.Key); e != nil {
			logger.Error(`E:`, e)
		} else {
			httpSer.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{cert},
				NextProtos:   []string{"h2", "http/1.1"},
			}
		}
	}
	if t.BlocksI == nil {
		if t.CopyBlocks == 0 {
			t.CopyBlocks = 1000
		}
		t.BlocksI = pslice.NewBlocks[byte](16*1024, t.CopyBlocks)
	}

	syncWeb := pweb.NewSyncMap(&httpSer, &routeP, matchfunc)
	defer syncWeb.Shutdown()

	var addRoute = func(route *Route) {
		logger.Info(`I:`, "路由加载", route.Path)
		routeP.Store(route.Path, func(w http.ResponseWriter, r *http.Request) {
			ctx1, done1 := pctx.WaitCtx(ctx)
			defer done1()

			if !Matched(route.MatchHeader, r) {
				w.WriteHeader(http.StatusNotFound)
			}

			var backIs []*Back
			if t, e := r.Cookie("_psign_" + cookie); e == nil {
				if backP, ok := route.backMap.Load(t.Value); ok && backP.(*Back).IsLive() && Matched(backP.(*Back).MatchHeader, r) {
					backP.(*Back).PathAdd = route.PathAdd
					backP.(*Back).Splicing = route.Splicing
					backP.(*Back).ReqHeader = append(route.ReqHeader, backP.(*Back).ReqHeader...)
					backP.(*Back).ResHeader = append(route.ResHeader, backP.(*Back).ResHeader...)
					for i := 0; i < backP.(*Back).Weight; i++ {
						backIs = append(backIs, backP.(*Back))
					}
				}
			}

			if len(backIs) == 0 {
				backIs = append(backIs, route.FiliterBackByRequest(r)...)
			}

			if len(backIs) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			rand.Shuffle(len(backIs), func(i, j int) {
				backIs[i], backIs[j] = backIs[j], backIs[i]
			})

			var e error
			if r.Header.Get("Upgrade") == "websocket" {
				e = wsDealer(ctx1, w, r, route.Path, backIs, logger, t.BlocksI)
			} else {
				e = httpDealer(ctx1, w, r, route.Path, backIs, logger, t.BlocksI)
			}
			if errors.Is(e, ErrHeaderCheckFail) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		})
	}

	var delRoute = func(route *Route) {
		logger.Info(`I:`, "路由移除", route.Path)
		routeP.Store(route.Path, nil)
	}

	t.SwapSign(addRoute, delRoute, logger)
	logger.Info(`I:`, "启动完成")
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 10):
			t.SwapSign(addRoute, delRoute, logger)
		}
	}
}

func (t *Config) SwapSign(add func(*Route), del func(*Route), logger Logger) {
	for i := 0; i < len(t.oldRoutes); i++ {
		var exist bool
		for k := 0; k < len(t.Routes); k++ {
			if t.oldRoutes[i].Path == t.Routes[k].Path {
				exist = true
				break
			}
		}
		if !exist {
			del(t.oldRoutes[i])
		}
	}

	for i := 0; i < len(t.Routes); i++ {
		var exist bool
		for k := 0; k < len(t.oldRoutes); k++ {
			if t.Routes[i].Path == t.oldRoutes[k].Path {
				exist = true
				break
			}
		}
		if !exist {
			add(&t.Routes[i])
		}
	}

	t.oldRoutes = t.oldRoutes[:0]

	for i := 0; i < len(t.Routes); i++ {
		t.Routes[i].SwapSign(
			func(b *Back) {
				logger.Info(`I:`, "后端加载", t.Routes[i].Path, b.Name)
				t.Routes[i].backMap.Store(b.Id(), b)
			},
			func(b *Back) {
				logger.Info(`I:`, "后端移除", t.Routes[i].Path, b.Name)
				t.Routes[i].backMap.Delete(b.Id())
			},
			logger,
		)
		t.oldRoutes = append(t.oldRoutes, &t.Routes[i])
	}
}

type Route struct {
	Path string `json:"path"`

	Splicing    int      `json:"splicing"`
	PathAdd     bool     `json:"pathAdd"`
	MatchHeader []Header `json:"matchHeader"`
	ReqHeader   []Header `json:"reqHeader"`
	ResHeader   []Header `json:"resHeader"`

	backMap sync.Map `json:"-"`
	Backs   []Back   `json:"backs"`
}

func (t *Route) SwapSign(add func(*Back), del func(*Back), logger Logger) {
	logger.Info(t.Path)
	t.backMap.Range(func(key, value any) bool {
		var exist bool
		for k := 0; k < len(t.Backs); k++ {
			if key.(string) == t.Backs[k].Id() {
				exist = true
				break
			}
		}
		if !exist {
			del(value.(*Back))
		}
		return true
	})

	for i := 0; i < len(t.Backs); i++ {
		if _, ok := t.backMap.Load(t.Backs[i].Id()); !ok {
			add(&t.Backs[i])
		}
	}
}

// func (t *Route) GenBack() []*Back {
// 	var backLink []*Back
// 	for i := 0; i < len(t.Back); i++ {
// 		back := &t.Back[i]
// 		back.SwapSign()
// 		if back.Weight == 0 {
// 			continue
// 		}
// 		tmpBack := Back{
// 			Name:        back.Name,
// 			Splicing:    t.Splicing,
// 			Sign:        back.Sign,
// 			To:          back.To,
// 			Weight:      back.Weight,
// 			ErrBanSec:   back.ErrBanSec,
// 			PathAdd:     t.PathAdd,
// 			MatchHeader: append(t.MatchHeader, back.MatchHeader...),
// 			ReqHeader:   append(t.ReqHeader, back.ReqHeader...),
// 			ResHeader:   append(t.ResHeader, back.ResHeader...),
// 		}
// 		for i := 1; i <= back.Weight; i++ {
// 			backLink = append(backLink, &tmpBack)
// 		}
// 	}
// 	return backLink
// }

func (t *Route) FiliterBackByRequest(r *http.Request) []*Back {
	var backLink []*Back
	for i := 0; i < len(t.Backs); i++ {
		if t.Backs[i].IsLive() && Matched(t.Backs[i].MatchHeader, r) {
			t.Backs[i].PathAdd = t.PathAdd
			t.Backs[i].Splicing = t.Splicing
			t.Backs[i].ReqHeader = append(t.ReqHeader, t.Backs[i].ReqHeader...)
			t.Backs[i].ResHeader = append(t.ResHeader, t.Backs[i].ResHeader...)
			for k := 0; k < t.Backs[i].Weight; k++ {
				backLink = append(backLink, &t.Backs[i])
			}
		}
	}
	return backLink
}

type Back struct {
	lock sync.RWMutex `json:"-"`
	upT  time.Time    `json:"-"`

	Name      string `json:"name"`
	To        string `json:"to"`
	Weight    int    `json:"weight"`
	ErrBanSec int    `json:"errBanSec"`

	Splicing    int      `json:"-"`
	PathAdd     bool     `json:"-"`
	MatchHeader []Header `json:"matchHeader"`
	ReqHeader   []Header `json:"reqHeader"`
	ResHeader   []Header `json:"resHeader"`
}

// func (t *Back) Init() (e error) {
// 	for i := 0; i < len(t.MatchHeader); i++ {
// 		e = t.MatchHeader[i].Init()
// 		if e != nil {
// 			return e
// 		}
// 	}
// 	for i := 0; i < len(t.ReqHeader); i++ {
// 		e = t.ReqHeader[i].Init()
// 		if e != nil {
// 			return e
// 		}
// 	}
// 	for i := 0; i < len(t.ResHeader); i++ {
// 		e = t.ResHeader[i].Init()
// 		if e != nil {
// 			return e
// 		}
// 	}
// 	return
// }

func (t *Back) Id() string {
	w := md5.New()
	w.Write([]byte(t.Name + t.To))
	return fmt.Sprintf("%x", w.Sum(nil))
}

func Matched(matchHeader []Header, r *http.Request) bool {
	matchs := len(matchHeader) - 1
	for ; matchs >= 0; matchs -= 1 {
		if !MatchedOne(matchHeader[matchs], r.Header.Get(matchHeader[matchs].Key)) {
			break
		}
	}
	return matchs == -1
}

func MatchedOne(matchHeader Header, value string) bool {
	if matchHeader.Value != "" && value != matchHeader.Value {
		return false
	}
	if matchHeader.MatchExp != "" {
		if regexp, e := regexp.Compile(matchHeader.MatchExp); e != nil || !regexp.MatchString(value) {
			return false
		}
	}
	return true
}

func (t *Back) IsLive() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.upT.Before(time.Now())
}

func (t *Back) Disable() {
	if t.ErrBanSec == 0 {
		t.ErrBanSec = 1
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	t.upT = time.Now().Add(time.Second * time.Duration(t.ErrBanSec))
}

type Header struct {
	Action   string `json:"action"`
	Key      string `json:"key"`
	MatchExp string `json:"matchExp"`
	Value    string `json:"value"`
}
