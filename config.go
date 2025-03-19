package front

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/qydysky/front/dealer"
	filiter "github.com/qydysky/front/filiter"
	component2 "github.com/qydysky/part/component2"
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
	RetryBlocks struct {
		Size string `json:"size"`
		size int    `json:"-"`
		Num  int    `json:"num"`
	} `json:"retryBlocks"`
	RetryBlocksI pslice.BlocksI[byte] `json:"-"`
	MatchRule    string               `json:"matchRule"`
	CopyBlocks   int                  `json:"copyBlocks"`
	BlocksI      pslice.BlocksI[byte] `json:"-"`

	routeP   pweb.WebPath
	routeMap sync.Map `json:"-"`
	Routes   []Route  `json:"routes"`

	ReqIdLoop int           `json:"reqIdLoop"`
	reqId     atomic.Uint32 `json:"-"`
}

func (t *Config) Run(ctx context.Context, logger Logger) {
	ctx, done := pctx.WithWait(ctx, 0, time.Minute)
	defer func() {
		_ = done()
	}()

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
	if t.ReqIdLoop <= 0 {
		t.ReqIdLoop = 1000
	} else if t.ReqIdLoop > math.MaxUint32 {
		t.ReqIdLoop = math.MaxUint32
	}

	if t.BlocksI == nil {
		if t.CopyBlocks == 0 {
			t.CopyBlocks = 1000
		}
		t.BlocksI = pslice.NewBlocks[byte](16*1024, t.CopyBlocks)
	}
	if size, err := humanize.ParseBytes(t.RetryBlocks.Size); err != nil || size < humanize.MByte {
		t.RetryBlocks.size = humanize.MByte
	} else {
		t.RetryBlocks.size = int(size)
	}
	if t.RetryBlocks.size > 0 && t.RetryBlocks.Num > 0 {
		t.RetryBlocksI = pslice.NewBlocks[byte](t.RetryBlocks.size, t.RetryBlocks.Num)
	}

	defer logger.Info(`I:`, fmt.Sprintf("%v shutdown", t.Addr))

	defer t.startServer(ctx, logger, &httpSer)()

	t.SwapSign(ctx, logger)
	logger.Info(`I:`, fmt.Sprintf("%v running", t.Addr))
	<-ctx.Done()
}

func (t *Config) startServer(ctx context.Context, logger Logger, conf *http.Server) (shutdown func(ctx ...context.Context)) {
	shutdown = func(ctx ...context.Context) {}

	var matchfunc func(path string) (func(w http.ResponseWriter, r *http.Request), bool)
	switch t.MatchRule {
	case "all":
		matchfunc = t.routeP.Load
	default:
		matchfunc = t.routeP.LoadPerfix
	}

	var hasErr = false

	timer := time.NewTicker(time.Millisecond * 100)
	defer timer.Stop()

	for {
		syncWeb, err := pweb.NewSyncMapNoPanic(conf, &t.routeP, matchfunc)
		if err == nil {
			shutdown = syncWeb.Shutdown
			return
		} else {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if !hasErr {
					hasErr = true
					logger.Warn(`W:`, fmt.Sprintf("%v. Retry...", err))
				}
			}
		}
	}
}

func (t *Config) SwapSign(ctx context.Context, logger Logger) {
	var add = func(k string, route *Route, logger Logger) {
		route.config = t
		if len(route.Path) == 0 {
			return
		}
		logger.Info(`I:`, fmt.Sprintf("%v > %v", t.Addr, k))
		t.routeMap.Store(k, route)

		var (
			logFormat         = "%d %v %v%v %v %v"
			logFormatWithBack = "%v %v %v%v > %v %v %v"
		)

		for _, routePath := range route.Path {
			t.routeP.Store(routePath, func(w http.ResponseWriter, r *http.Request) {

				reqId := t.reqId.Add(1)
				if reqId >= uint32(t.ReqIdLoop) {
					t.reqId.Store(0)
				}

				if len(r.RequestURI) > 8000 {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "BLOCK", ErrUriTooLong))
					w.Header().Add(header+"Error", ErrUriTooLong.Error())
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				if ok, e := route.Filiter.ReqUri.Match(r); e != nil {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", e))
				} else if !ok {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "BLOCK", ErrPatherCheckFail))
					w.Header().Add(header+"Error", ErrPatherCheckFail.Error())
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if ok, e := route.Filiter.ReqHeader.Match(r.Header); e != nil {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", e))
				} else if !ok {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "BLOCK", ErrHeaderCheckFail))
					w.Header().Add(header+"Error", ErrHeaderCheckFail.Error())
					w.WriteHeader(http.StatusForbidden)
					return
				}

				if ok, e := route.Filiter.ReqBody.Match(r); e != nil {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", e))
				} else if !ok {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "BLOCK", ErrBodyCheckFail))
					w.Header().Add(header+"Error", ErrBodyCheckFail.Error())
					w.WriteHeader(http.StatusForbidden)
					return
				}

				var (
					backIs    []*Back
					backEqual = func(a, b *Back) bool {
						return a == b
					}
				)

				{
					if t, e := r.Cookie("_psign_" + cookie); e == nil {
						if backP, aok := route.backMap.Load(t.Value); aok {
							var filiter = func(b *Back) (error, bool) {
								if ok, e := b.getFiliterReqUri().Match(r); e != nil || !ok {
									return e, ok
								}

								if ok, e := b.getFiliterReqHeader().Match(r.Header); e != nil || !ok {
									return e, ok
								}
								return nil, true
							}

							if e, ok := filiter(backP.(*Back)); e != nil {
								logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", e))
							} else if ok {
								for i := uint(0); i < backP.(*Back).Weight; i++ {
									backIs = addIfNotExsit(backIs, backEqual, backP.(*Back))
								}
							}
						}
					}

					var splicingC = len(backIs)

					backIs = addIfNotExsit(backIs, backEqual, route.FiliterBackByRequest(r)...)

					if f, ok := rollRuleMap[route.RollRule]; ok {
						f(backIs[splicingC:])
					} else {
						rand_Shuffle(backIs[splicingC:])
					}
				}

				if len(backIs) == 0 {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "BLOCK", ErrNoRoute))
					w.Header().Add(header+"Error", ErrNoRoute.Error())
					w.WriteHeader(http.StatusNotFound)
					return
				}

				var e error = ErrAllBacksFail

				type reqDealer interface {
					Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error
				}

				// repack
				var (
					reqBuf     []byte
					reqBufUsed bool
				)
				if t.RetryBlocksI != nil && r.Body != nil {
					if contentLength := r.Header.Get("Content-Length"); contentLength != "" {
						if len, e := strconv.Atoi(contentLength); e == nil && t.RetryBlocks.size >= len {
							var putBack func()
							var e error
							reqBuf, putBack, e = t.RetryBlocksI.Get()
							if e == nil {
								defer putBack()
								reqBufUsed = true
								n, _ := r.Body.Read(reqBuf)
								reqBuf = reqBuf[:n]
							} else {
								logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", ErrReqReBodyOverflow))
							}
						}
					}
				}

				for _, backP := range backIs {
					if !backP.IsLive() {
						continue
					}

					backP.lock.Lock()
					backP.lastChosenT = time.Now()
					backP.lock.Unlock()

					if reqBufUsed {
						r.Body = io.NopCloser(bytes.NewBuffer(reqBuf))
					}

					if !strings.Contains(backP.To, "://") {
						e = component2.Get[reqDealer]("local").Deal(r.Context(), reqId, w, r, routePath, backP, logger, t.BlocksI)
					} else if strings.ToLower((r.Header.Get("Upgrade"))) == "websocket" {
						e = component2.Get[reqDealer]("ws").Deal(r.Context(), reqId, w, r, routePath, backP, logger, t.BlocksI)
					} else {
						e = component2.Get[reqDealer]("http").Deal(r.Context(), reqId, w, r, routePath, backP, logger, t.BlocksI)
					}

					if e == nil {
						// no err
						break
					}

					if v, ok := e.(ErrCanRetry); !ok || !v.CanRetry {
						// some err can't retry
						break
					}

					logger.Warn(`W:`, fmt.Sprintf(logFormatWithBack, reqId, r.RemoteAddr, route.config.Addr, routePath, backP.Name, "ErrCanRetry", e))
				}

				if e != nil {
					w.Header().Add(header+"Error", e.Error())
					if errors.Is(e, ErrHeaderCheckFail) || errors.Is(e, ErrBodyCheckFail) {
						w.WriteHeader(http.StatusForbidden)
					} else {
						if errors.Is(e, ErrAllBacksFail) {
							w.WriteHeader(http.StatusBadGateway)
						} else {
							t.routeP.GetConn(r).Close()
						}
						logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", e))
					}
				}
			})
		}
	}

	var del = func(k string, _ *Route, logger Logger) {
		logger.Info(`I:`, fmt.Sprintf("%v x %v", t.Addr, k))
		t.routeMap.Delete(k)
		t.routeP.Store(k, nil)
	}

	t.routeMap.Range(func(key, value any) bool {
		var exist bool
		for k := 0; k < len(t.Routes) && !exist; k++ {
			for _, routePath := range t.Routes[k].Path {
				if key.(string) == routePath {
					exist = true
					break
				}
			}
		}
		if !exist {
			del(key.(string), value.(*Route), logger)
		}
		return true
	})

	for i := 0; i < len(t.Routes); i++ {
		for _, routePath := range t.Routes[i].Path {
			if _, ok := t.routeMap.Load(routePath); !ok {
				add(routePath, &t.Routes[i], logger)
			}
		}
		t.Routes[i].SwapSign(logger)
	}
}

type ErrCanRetry struct {
	error
	CanRetry bool
}

func MarkRetry(e error) error {
	return ErrCanRetry{
		error:    e,
		CanRetry: true,
	}
}

type Route struct {
	config *Config  `json:"-"`
	Path   []string `json:"path"`

	PathAdd  bool   `json:"pathAdd"`
	RollRule string `json:"rollRule"`
	// ReqBody  filiter.Body `json:"reqBody"`
	Setting

	backMap sync.Map `json:"-"`
	Backs   []Back   `json:"backs"`
}

func (t *Route) Id() string {
	return fmt.Sprintf("%p", t)
}

func (t *Route) SwapSign(logger Logger) {
	if len(t.Path) == 0 {
		return
	}
	t.backMap.Range(func(key, value any) bool {
		var exist bool
		for k := 0; k < len(t.Backs); k++ {
			if key.(string) == t.Backs[k].Id() {
				exist = true
				break
			}
		}
		if !exist {
			logger.Info(`I:`, fmt.Sprintf("%v > %v x %v", t.config.Addr, t.Path, value.(*Back).Name))
			t.backMap.Delete(key)
		}
		return true
	})

	for i := 0; i < len(t.Backs); i++ {
		if _, ok := t.backMap.Load(t.Backs[i].Id()); !ok {
			t.Backs[i].route = t
			logger.Info(`I:`, fmt.Sprintf("%v > %v > %v", t.config.Addr, t.Path, t.Backs[i].Name))
			t.backMap.Store(t.Backs[i].Id(), &t.Backs[i])
		}
		t.Backs[i].SwapSign(logger)
	}
}

func (t *Route) FiliterBackByRequest(r *http.Request) []*Back {
	var backLink []*Back
	for i := 0; i < len(t.Backs); i++ {
		if ok, e := t.Backs[i].getFiliterReqUri().Match(r); !ok || e != nil {
			continue
		}

		if ok, e := t.Backs[i].getFiliterReqHeader().Match(r.Header); !ok || e != nil {
			continue
		}

		if !t.Backs[i].AlwaysUp && t.Backs[i].Weight == 0 {
			continue
		}

		t.Backs[i].route = t
		backLink = append(backLink, &t.Backs[i])
	}

	return backLink
}

type Back struct {
	route       *Route       `json:"-"`
	lock        sync.RWMutex `json:"-"`
	upT         time.Time    `json:"-"`
	lastChosenT time.Time    `json:"-"`
	disableC    uint         `json:"-"`
	dealingC    uint         `json:"-"`
	chosenC     uint         `json:"-"`

	lastResDru time.Duration `json:"-"`

	Name     string `json:"name"`
	To       string `json:"to"`
	Weight   uint   `json:"weight,string"`
	AlwaysUp bool   `json:"alwaysUp"`

	Setting
}

func (t *Back) SwapSign(logger Logger) {
	path := t.VerifyPeerCer
	if path == "" {
		path = t.route.VerifyPeerCer
	}
	if path == "" {
		t.verifyPeerCerErr = ErrEmptyVerifyPeerCerByte
		t.verifyPeerCer = nil
	} else {
		t.verifyPeerCer, t.verifyPeerCerErr = os.ReadFile(path)
	}
	if t.lastChosenT.IsZero() {
		t.lastChosenT = time.Now()
	}
	t.AlwaysUp = len(t.route.Backs) == 1 || t.AlwaysUp
}

func (t *Back) getSplicing() int {
	if t.Splicing == 0 {
		return t.route.Splicing
	}
	return t.Splicing
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
func (t *Back) getInsecureSkipVerify() bool {
	return t.route.InsecureSkipVerify || t.InsecureSkipVerify
}
func (t *Back) getVerifyPeerCer() (cer []byte, e error) {
	return t.verifyPeerCer, t.verifyPeerCerErr
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

//	func (t *Back) getFiliterResBody() *filiter.Body {
//		if !t.Filiter.ReqBody.Valid() {
//			return &t.route.Filiter.ReqBody
//		} else {
//			return &t.Filiter.ReqBody
//		}
//	}
func (t *Back) getDealerReqUri() []dealer.UriDealer {
	return append(t.route.Dealer.ReqUri, t.Dealer.ReqUri...)
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
	t.dealingC += 1
	t.lock.Unlock()
}

func (t *Back) ed() {
	t.lock.Lock()
	t.dealingC -= 1
	t.lock.Unlock()
}

func (t *Back) IsLive() bool {
	if t.AlwaysUp {
		return true
	}
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.upT.Before(time.Now())
}

func (t *Back) Disable() {
	if t.AlwaysUp {
		return
	}
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
	ErrToSec           float64         `json:"errToSec"`
	Splicing           int             `json:"splicing"`
	ErrBanSec          int             `json:"errBanSec"`
	InsecureSkipVerify bool            `json:"insecureSkipVerify"`
	VerifyPeerCer      string          `json:"verifyPeerCer"`
	Filiter            filiter.Filiter `json:"filiter"`
	Dealer             dealer.Dealer   `json:"dealer"`
	verifyPeerCer      []byte
	verifyPeerCerErr   error
}

var (
	ErrEmptyVerifyPeerCerByte = errors.New("ErrEmptyVerifyPeerCerByte")
)

func LoadX509PubKey(certPEMBlock []byte) tls.Certificate {
	var cert tls.Certificate
	for {
		var certDERBlock *pem.Block
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}
	return cert
}

func addIfNotExsit[T []E, E any](s T, equal func(a, b E) bool, e ...E) T {
	for j := 0; j < len(e); j++ {
		if len(s) == 0 {
			s = append(s, e[j])
		} else {
			for i := 0; i < len(s); i++ {
				if !equal(s[i], e[j]) {
					s = append(s, e[j])
					break
				}
			}
		}
	}
	return s
}
