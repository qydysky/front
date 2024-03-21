package front

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/qydysky/front/dealer"
	filiter "github.com/qydysky/front/filiter"
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

	routeP   pweb.WebPath
	routeMap sync.Map `json:"-"`
	Routes   []Route  `json:"routes"`
}

func (t *Config) Run(ctx context.Context, logger Logger) {
	ctx, done := pctx.WithWait(ctx, 0, time.Minute)
	defer func() {
		_ = done()
	}()

	var matchfunc func(path string) (func(w http.ResponseWriter, r *http.Request), bool)
	switch t.MatchRule {
	case "all":
		matchfunc = t.routeP.Load
	default:
		matchfunc = t.routeP.LoadPerfix
	}

	httpSer := http.Server{
		Addr:        t.Addr,
		BaseContext: func(l net.Listener) context.Context { return ctx },
	}
	if t.TLS.Key != "" && t.TLS.Pub != "" {
		if cert, e := tls.LoadX509KeyPair(t.TLS.Pub, t.TLS.Key); e != nil {
			logger.Error(`E:`, fmt.Sprintf("%v %v", t.Addr, e))
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

	syncWeb := pweb.NewSyncMap(&httpSer, &t.routeP, matchfunc)
	defer syncWeb.Shutdown()

	t.SwapSign(ctx, logger)
	logger.Info(`I:`, fmt.Sprintf("%v running", t.Addr))
	<-ctx.Done()
	logger.Info(`I:`, fmt.Sprintf("%v shutdown", t.Addr))
}

func (t *Config) SwapSign(ctx context.Context, logger Logger) {
	var add = func(k string, route *Route, logger Logger) {
		route.config = t
		logger.Info(`I:`, fmt.Sprintf("%v > %v", t.Addr, k))
		t.routeMap.Store(k, route)

		var logFormat = "%v%v %v %v"

		t.routeP.Store(route.Path, func(w http.ResponseWriter, r *http.Request) {
			if len(r.RequestURI) > 8000 {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "BLOCK", ErrUriTooLong))
				w.Header().Add(header+"Error", ErrUriTooLong.Error())
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if ok, e := route.Filiter.ReqUri.Match(r); e != nil {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "Err", e))
			} else if !ok {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "BLOCK", ErrPatherCheckFail))
				w.Header().Add(header+"Error", ErrPatherCheckFail.Error())
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if ok, e := route.Filiter.ReqHeader.Match(r.Header); e != nil {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "Err", e))
			} else if !ok {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "BLOCK", ErrHeaderCheckFail))
				w.Header().Add(header+"Error", ErrHeaderCheckFail.Error())
				w.WriteHeader(http.StatusForbidden)
				return
			}

			if ok, e := route.ReqBody.Match(r); e != nil {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "Err", e))
			} else if !ok {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "BLOCK", ErrBodyCheckFail))
				w.Header().Add(header+"Error", ErrBodyCheckFail.Error())
				w.WriteHeader(http.StatusForbidden)
				return
			}

			var backIs []*Back

			if t, e := r.Cookie("_psign_" + cookie); e == nil {
				if backP, aok := route.backMap.Load(t.Value); aok {

					if ok, e := backP.(*Back).getFiliterReqUri().Match(r); e != nil {
						logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "Err", e))
					} else if ok {
						aok = false
					}

					if ok, e := backP.(*Back).getFiliterReqHeader().Match(r.Header); e != nil {
						logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "Err", e))
					} else if ok {
						aok = false
					}

					if aok {
						for i := 0; i < backP.(*Back).Weight; i++ {
							backIs = append(backIs, backP.(*Back))
						}
					}
				}
			}

			backIs = append(backIs, route.FiliterBackByRequest(r)...)

			if len(backIs) == 0 {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, route.config.Addr, route.Path, "BLOCK", ErrNoRoute))
				w.Header().Add(header+"Error", ErrNoRoute.Error())
				w.WriteHeader(http.StatusNotFound)
				return
			}

			var e error
			if strings.ToLower((r.Header.Get("Upgrade"))) == "websocket" {
				e = wsDealer(r.Context(), w, r, route.Path, backIs, logger, t.BlocksI)
			} else {
				e = httpDealer(r.Context(), w, r, route.Path, backIs, logger, t.BlocksI)
			}
			if e != nil {
				w.Header().Add(header+"Error", e.Error())
				if errors.Is(e, ErrHeaderCheckFail) || errors.Is(e, ErrBodyCheckFail) {
					w.WriteHeader(http.StatusForbidden)
				} else if errors.Is(e, ErrAllBacksFail) {
					w.WriteHeader(http.StatusBadGateway)
					os.Exit(0)
				} else {
					t.routeP.GetConn(r).Close()
				}
			}
		})
	}

	var del = func(k string, _ *Route, logger Logger) {
		logger.Info(`I:`, fmt.Sprintf("%v x %v", t.Addr, k))
		t.routeMap.Delete(k)
		t.routeP.Store(k, nil)
	}

	var routeU = func(route *Route, logger Logger) {
		route.SwapSign(
			func(k string, b *Back) {
				b.route = route
				logger.Info(`I:`, fmt.Sprintf("%v > %v > %v", t.Addr, route.Path, b.Name))
				route.backMap.Store(k, b)
			},
			func(k string, b *Back) {
				logger.Info(`I:`, fmt.Sprintf("%v > %v x %v", t.Addr, route.Path, b.Name))
				route.backMap.Delete(k)
			},
			logger,
		)
	}

	t.routeMap.Range(func(key, value any) bool {
		var exist bool
		for k := 0; k < len(t.Routes); k++ {
			if key.(string) == t.Routes[k].Path {
				exist = true
				break
			}
		}
		if !exist {
			del(key.(string), value.(*Route), logger)
		}
		return true
	})

	for i := 0; i < len(t.Routes); i++ {
		if _, ok := t.routeMap.Load(t.Routes[i].Path); !ok {
			routeU(&t.Routes[i], logger)
			add(t.Routes[i].Path, &t.Routes[i], logger)
		}
	}
}

type Route struct {
	config *Config `json:"-"`
	Path   string  `json:"path"`

	PathAdd  bool         `json:"pathAdd"`
	RollRule string       `json:"rollRule"`
	ReqBody  filiter.Body `json:"reqBody"`
	Setting

	backMap sync.Map `json:"-"`
	Backs   []Back   `json:"backs"`
}

func (t *Route) Id() string {
	return fmt.Sprintf("%p", t)
}

func (t *Route) SwapSign(add func(string, *Back), del func(string, *Back), logger Logger) {
	t.backMap.Range(func(key, value any) bool {
		var exist bool
		for k := 0; k < len(t.Backs); k++ {
			if key.(string) == t.Backs[k].Id() {
				exist = true
				break
			}
		}
		if !exist {
			del(key.(string), value.(*Back))
		}
		return true
	})

	for i := 0; i < len(t.Backs); i++ {
		if _, ok := t.backMap.Load(t.Backs[i].Id()); !ok {
			add(t.Backs[i].Id(), &t.Backs[i])
		}
	}
}

func (t *Route) FiliterBackByRequest(r *http.Request) []*Back {
	var backLink []*Back
	for i := 0; i < len(t.Backs); i++ {
		if ok, e := t.Backs[i].getFiliterReqHeader().Match(r.Header); ok && e == nil {
			t.Backs[i].route = t
			for k := 0; k < t.Backs[i].Weight; k++ {
				backLink = append(backLink, &t.Backs[i])
			}
		}
	}

	if f, ok := rollRuleMap[t.RollRule]; ok {
		f(backLink)
	} else {
		rand_Shuffle(backLink)
	}

	return backLink
}

type Back struct {
	route      *Route        `json:"-"`
	lock       sync.RWMutex  `json:"-"`
	upT        time.Time     `json:"-"`
	disableC   int           `json:"-"`
	dealingC   int           `json:"-"`
	chosenC    int           `json:"-"`
	lastResDru time.Duration `json:"-"`
	resDru     time.Duration `json:"-"`

	Name   string `json:"name"`
	To     string `json:"to"`
	Weight int    `json:"weight"`

	Setting
}

func (t *Back) Splicing() int {
	return t.route.Splicing
}
func (t *Back) PathAdd() bool {
	return t.route.PathAdd
}
func (t *Back) getErrBanSec() int {
	if t.ErrBanSec == 0 {
		return t.route.ErrBanSec
	} else {
		return t.ErrBanSec
	}
}
func (t *Back) getErrToSec() float64 {
	if t.ErrToSec == 0 {
		return t.route.ErrToSec
	} else {
		return t.ErrToSec
	}
}
func (t *Back) getFiliterReqHeader() *filiter.Header {
	if !t.Filiter.ReqHeader.Valid() {
		return &t.route.Filiter.ReqHeader
	} else {
		return &t.Filiter.ReqHeader
	}
}
func (t *Back) getFiliterReqUri() *filiter.Uri {
	if !t.Filiter.ReqUri.Valid() {
		return &t.route.Filiter.ReqUri
	} else {
		return &t.Filiter.ReqUri
	}
}
func (t *Back) getFiliterResHeader() *filiter.Header {
	if !t.Filiter.ResHeader.Valid() {
		return &t.route.Filiter.ResHeader
	} else {
		return &t.Filiter.ResHeader
	}
}
func (t *Back) getDealerReqHeader() []dealer.HeaderDealer {
	return append(t.route.Dealer.ReqHeader, t.Dealer.ReqHeader...)
}
func (t *Back) getDealerResHeader() []dealer.HeaderDealer {
	return append(t.route.Dealer.ResHeader, t.Dealer.ResHeader...)
}

func (t *Back) Id() string {
	return fmt.Sprintf("%p", t)
}

func (t *Back) be(opT time.Time) {
	t.lock.Lock()
	t.chosenC += 1
	t.lastResDru = time.Since(opT)
	t.resDru += t.lastResDru
	t.dealingC += 1
	t.lock.Unlock()
}

func (t *Back) ed() {
	t.lock.Lock()
	t.dealingC -= 1
	t.lock.Unlock()
}

func (t *Back) IsLive() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.upT.Before(time.Now())
}

func (t *Back) Disable() {
	tmp := t.getErrBanSec()
	if tmp == 0 {
		tmp = 1
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	t.disableC += 1
	t.upT = time.Now().Add(time.Second * time.Duration(tmp))
}

type Setting struct {
	ErrToSec  float64         `json:"errToSec"`
	Splicing  int             `json:"splicing"`
	ErrBanSec int             `json:"errBanSec"`
	Filiter   filiter.Filiter `json:"filiter"`
	Dealer    dealer.Dealer   `json:"dealer"`
}
