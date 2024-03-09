package front

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/dustin/go-humanize"
	pctx "github.com/qydysky/part/ctx"
	pio "github.com/qydysky/part/io"
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
	defer done()

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

		t.routeP.Store(route.Path, func(w http.ResponseWriter, r *http.Request) {
			if !HeaderMatchs(route.ReqHeader, r) {
				w.WriteHeader(http.StatusNotFound)
			}

			var backIs []*Back
			if t, e := r.Cookie("_psign_" + cookie); e == nil {
				if backP, ok := route.backMap.Load(t.Value); ok && backP.(*Back).IsLive() && HeaderMatchs(backP.(*Back).ReqHeader, r) {
					backP.(*Back).PathAdd = route.PathAdd
					backP.(*Back).Splicing = route.Splicing
					backP.(*Back).tmp.ReqHeader = append(route.ReqHeader, backP.(*Back).ReqHeader...)
					backP.(*Back).tmp.ResHeader = append(route.ResHeader, backP.(*Back).ResHeader...)
					backP.(*Back).tmp.ReqBody = append(route.ReqBody, backP.(*Back).ReqBody...)
					for i := 0; i < backP.(*Back).Weight; i++ {
						backIs = append(backIs, backP.(*Back))
					}
				}
			}

			backIs = append(backIs, route.FiliterBackByRequest(r)...)

			if len(backIs) == 0 {
				w.WriteHeader(http.StatusNotFound)
				return
			}

			var e error
			if r.Header.Get("Upgrade") == "websocket" {
				e = wsDealer(r.Context(), w, r, route.Path, backIs, logger, t.BlocksI)
			} else {
				e = httpDealer(r.Context(), w, r, route.Path, backIs, logger, t.BlocksI)
			}
			if e != nil {
				w.Header().Add(header+"Error", e.Error())
			}
			if errors.Is(e, ErrHeaderCheckFail) || errors.Is(e, ErrBodyCheckFail) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		})
	}

	var del = func(k string, route *Route, logger Logger) {
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

	Splicing int  `json:"splicing"`
	PathAdd  bool `json:"pathAdd"`
	Matcher

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
		if t.Backs[i].IsLive() && HeaderMatchs(t.Backs[i].ReqHeader, r) {
			t.Backs[i].PathAdd = t.PathAdd
			t.Backs[i].Splicing = t.Splicing
			t.Backs[i].tmp.ReqHeader = append(t.ReqHeader, t.Backs[i].ReqHeader...)
			t.Backs[i].tmp.ResHeader = append(t.ResHeader, t.Backs[i].ResHeader...)
			t.Backs[i].tmp.ReqBody = append(t.ReqBody, t.Backs[i].ReqBody...)
			for k := 0; k < t.Backs[i].Weight; k++ {
				backLink = append(backLink, &t.Backs[i])
			}
		}
	}
	rand.Shuffle(len(backLink), func(i, j int) {
		backLink[i], backLink[j] = backLink[j], backLink[i]
	})
	return backLink
}

type Back struct {
	route *Route       `json:"-"`
	lock  sync.RWMutex `json:"-"`
	upT   time.Time    `json:"-"`

	Name      string `json:"name"`
	To        string `json:"to"`
	Weight    int    `json:"weight"`
	ErrBanSec int    `json:"errBanSec"`

	Splicing int  `json:"-"`
	PathAdd  bool `json:"-"`
	Matcher
	tmp Matcher `json:"-"`
}

func (t *Back) Id() string {
	return fmt.Sprintf("%p", t)
}

func HeaderMatchs(matchHeader []Header, r *http.Request) bool {
	matchs := len(matchHeader) - 1
	for ; matchs >= 0; matchs -= 1 {
		if !matchHeader[matchs].Match(r.Header.Get(matchHeader[matchs].Key)) {
			break
		}
	}
	return matchs == -1
}

func BodyMatchs(matchBody []Body, r *http.Request) (reader io.ReadCloser, e error) {
	reader = r.Body
	for i := 0; i < len(matchBody); i++ {
		reader, e = matchBody[i].Match(reader)
		if e != nil {
			return
		}
	}
	return
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

type Matcher struct {
	ReqHeader []Header `json:"reqHeader"`
	ResHeader []Header `json:"resHeader"`
	ReqBody   []Body   `json:"reqBody"`
}

type Header struct {
	Action   string `json:"action"`
	Key      string `json:"key"`
	MatchExp string `json:"matchExp"`
	Value    string `json:"value"`
}

func (t *Header) Match(value string) bool {
	if t.Action != "access" && t.Action != "deny" {
		return true
	}
	if t.MatchExp != "" {
		if exp, e := regexp.Compile(t.MatchExp); e != nil || !exp.MatchString(value) {
			return t.Action == "deny"
		}
	}
	return t.Action == "access"
}

type Body struct {
	Action   string `json:"action"`
	ReqSize  string `json:"reqSize"`
	MatchExp string `json:"matchExp"`
}

func (t *Body) Match(r io.ReadCloser) (d io.ReadCloser, err error) {
	if exp, e := regexp.Compile(t.MatchExp); e == nil {
		if t.ReqSize == "" {
			t.ReqSize = "1M"
		}

		var (
			size, err = humanize.ParseBytes(t.ReqSize)
			buf       = make([]byte, size)
			n         int
		)

		if err != nil {
			return nil, err
		}

		for n < int(size) && err == nil {
			var nn int
			nn, err = r.Read(buf[n:])
			n += nn
		}
		if n >= int(size) {
			return nil, errors.New("body overflow")
		} else if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		buf = buf[:n]

		switch t.Action {
		case "access":
			if !exp.Match(buf) {
				return nil, errors.New("body deny")
			}
		case "deny":
			if exp.Match(buf) {
				return nil, errors.New("body deny")
			}
		}

		return pio.RWC{
			R: bytes.NewReader(buf).Read,
			C: func() error { return nil },
		}, nil
	} else {
		return nil, e
	}
}
