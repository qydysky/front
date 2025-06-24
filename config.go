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
	"unique"

	"github.com/dustin/go-humanize"
	"github.com/qydysky/front/dealer"
	filiter "github.com/qydysky/front/filiter"
	component2 "github.com/qydysky/part/component2"
	pctx "github.com/qydysky/part/ctx"
	pfile "github.com/qydysky/part/file"
	pio "github.com/qydysky/part/io"
	reqf "github.com/qydysky/part/reqf"
	pslice "github.com/qydysky/part/slice"
	pweb "github.com/qydysky/part/web"
)

var ErrDuplicatePath = errors.New(`ErrDuplicatePath`)

type Config struct {
	lock sync.RWMutex `json:"-"`
	Addr string       `json:"addr"`
	TLS  struct {
		Pub string `json:"pub"`
		Key string `json:"key"`
	} `json:"tls"`
	RetryBlocks  Blocks               `json:"retryBlocks"`
	RetryBlocksI pslice.BlocksI[byte] `json:"-"`
	MatchRule    string               `json:"matchRule"`
	FdPath       string               `json:"fdPath"`
	CopyBlocks   Blocks               `json:"copyBlocks"`
	BlocksI      pslice.BlocksI[byte] `json:"-"`

	routeP   pweb.WebPath
	routePR  sync.Map `json:"-"`
	routeMap sync.Map `json:"-"`
	Routes   []Route  `json:"routes"`

	ReqIdLoop int           `json:"reqIdLoop"`
	reqId     atomic.Uint32 `json:"-"`
}

type Blocks struct {
	Size string `json:"size"`
	size int    `json:"-"`
	Num  int    `json:"num"`
}

func (t *Config) Run(ctx context.Context, logger Logger) (e error, runf func()) {

	ctx, done := pctx.WithWait(ctx, 0, time.Minute)

	httpSer := http.Server{
		Addr:        t.Addr,
		BaseContext: func(l net.Listener) context.Context { return ctx },
	}
	if t.TLS.Key != "" && t.TLS.Pub != "" {
		var (
			pub    []byte
			pri    []byte
			errPub error
			errPri error
		)
		if !strings.HasPrefix(t.TLS.Pub, "http://") && !strings.HasPrefix(t.TLS.Pub, "https://") {
			pf := pfile.New(t.TLS.Pub, 0, false)
			pub, errPub = pf.ReadAll(humanize.KByte, humanize.MByte)
			if errors.Is(errPub, io.EOF) {
				errPub = nil
			}
		} else {
			r := reqf.New()
			errPub = r.Reqf(reqf.Rval{
				Url: t.TLS.Pub,
			})
			pub = r.Respon
		}
		if !strings.HasPrefix(t.TLS.Key, "http://") && !strings.HasPrefix(t.TLS.Key, "https://") {
			pf := pfile.New(t.TLS.Key, 0, false)
			pri, errPri = pf.ReadAll(humanize.KByte, humanize.MByte)
			if errors.Is(errPri, io.EOF) {
				errPri = nil
			}
		} else {
			r := reqf.New()
			errPri = r.Reqf(reqf.Rval{
				Url: t.TLS.Key,
			})
			pri = r.Respon
		}
		if errPub != nil || errPri != nil {
			logger.Error(`E:`, fmt.Sprintf("%v errPub(%v) errPri(%v)", t.Addr, errPub, errPri))
		} else if cert, e := tls.X509KeyPair(pub, pri); e != nil {
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
		if t.CopyBlocks.Num == 0 {
			t.CopyBlocks.Num = 1000
		}
		if size, err := humanize.ParseBytes(t.CopyBlocks.Size); err == nil && size > 0 {
			t.CopyBlocks.size = int(size)
		} else {
			t.CopyBlocks.size = humanize.KByte * 16
		}
		t.BlocksI = pslice.NewBlocks[byte](t.CopyBlocks.size, t.CopyBlocks.Num)
	}
	if size, err := humanize.ParseBytes(t.RetryBlocks.Size); err == nil && size > 0 {
		t.RetryBlocks.size = int(size)
	} else {
		t.RetryBlocks.size = humanize.MByte
	}
	if t.RetryBlocks.size > 0 && t.RetryBlocks.Num > 0 {
		t.RetryBlocksI = pslice.NewBlocks[byte](t.RetryBlocks.size, t.RetryBlocks.Num)
	}

	t.SwapSign(ctx, logger)
	logger.Info(`I:`, fmt.Sprintf("%v running", t.Addr))
	return nil, func() {
		shutdown := t.startServer(ctx, logger, &httpSer)
		<-ctx.Done()
		shutdown()
		logger.Info(`I:`, fmt.Sprintf("%v shutdown", t.Addr))
		_ = done()
	}
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

func (t *Config) addPath(route *Route, routePath string, logger Logger) {
	var (
		logFormat         = "%d %v %v%v %v %v"
		logFormatWithBack = "%v %v %v%v > %v %v %v"
	)

	logger.Info(`I:`, fmt.Sprintf("%v > %v", t.Addr, routePath))
	t.routePR.Store(routePath, route.Id())
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
						backIs = addIfNotExsit(backIs, backEqual, backP.(*Back))
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
			reqBuf           []byte
			reqBufUsed       bool
			reqAllRead       bool
			reqContentLength string = r.Header.Get("Content-Length")
			delayBody        io.ReadCloser
		)
		if t.RetryBlocksI != nil && r.Body != nil {
			if reqContentLength != "" {
				if n, e := strconv.Atoi(reqContentLength); e == nil && n < t.RetryBlocks.size {
					var putBack func()
					var e error
					reqBuf, putBack, e = t.RetryBlocksI.Get()
					if e == nil {
						defer putBack()
						reqBufUsed = true

						offset := 0
						for offset < cap(reqBuf) {
							n, e := r.Body.Read(reqBuf[offset:])
							offset += n
							if e != nil {
								if !errors.Is(e, io.EOF) {
									logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", e))
									w.Header().Add(header+"Error", ErrNoRoute.Error())
									w.WriteHeader(http.StatusBadRequest)
									return
								}
								reqAllRead = true
								break
							} else if n == 0 {
								break
							}
						}
						reqBuf = reqBuf[:offset]
						if !reqAllRead {
							delayBody = r.Body
							logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, route.config.Addr, routePath, "Err", ErrReqReBodyFull))
						}
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
				if !reqAllRead {
					r.Body = pio.RWC{
						R: io.MultiReader(bytes.NewBuffer(reqBuf), delayBody).Read,
						C: delayBody.Close,
					}
					reqBufUsed = false
				} else {
					r.Body = io.NopCloser(bytes.NewBuffer(reqBuf))
				}
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

			if errors.Is(e, context.Canceled) {
				e = nil
				break
			}

			if v, ok := e.(ErrCanRetry); !ok || !v.CanRetry {
				// some err can't retry
				break
			} else if reqContentLength != "" && !reqBufUsed {
				// has body but buf no allow reuse
				break
			}

			logger.Debug(`T:`, fmt.Sprintf(logFormatWithBack, reqId, r.RemoteAddr, route.config.Addr, routePath, backP.Name, "ErrCanRetry", e))
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

func (t *Config) delPath(routePath string, logger Logger) {
	logger.Info(`I:`, fmt.Sprintf("%v x %v", t.Addr, routePath))
	t.routeP.Delete(routePath)
	t.routePR.Delete(routePath)
}

func (t *Config) SwapSign(ctx context.Context, logger Logger) {
	var add = func(route *Route, logger Logger) {
		route.config = t

		var someValid = false
		for _, routePath := range route.Path {
			if _, ok := t.routePR.Load(routePath); ok {
				logger.Info(`I:`, fmt.Sprintf("%v ~ %v", t.Addr, route.Path))
				continue
			}
			if !someValid {
				t.routeMap.Store(route.Id(), route)
				someValid = true
			}
			t.addPath(route, routePath, logger)
		}
	}

	var del = func(route *Route, logger Logger) {
		t.routeMap.Delete(route.Id())
		for _, routePath := range route.Path {
			t.delPath(routePath, logger)
		}
	}

	// add new route
	for k := 0; k < len(t.Routes); k++ {
		if _, ok := t.routeMap.Load(t.Routes[k].Id()); !ok {
			add(&t.Routes[k], logger)
		}
	}

	// del no exist route
	t.routeMap.Range(func(key, value any) bool {
		var exist bool
		for k := 0; k < len(t.Routes) && !exist; k++ {
			if key.(string) == t.Routes[k].Id() {
				exist = true
				break
			}
		}
		if !exist {
			del(value.(*Route), logger)
		}
		return true
	})

	t.routeMap.Range(func(key, value any) bool {
		cid := value.(*Route).Id()
		// add new path
		for _, path := range value.(*Route).Path {
			if id, ok := t.routePR.Load(path); ok {
				if id.(string) != cid {
					logger.Info(`I:`, fmt.Sprintf("%v ~ %v", t.Addr, path))
				}
				continue
			} else {
				t.addPath(value.(*Route), path, logger)
			}
		}
		//del not exist path
		t.routePR.Range(func(key, id any) bool {
			if id.(string) == cid {
				var exist bool
				for _, path := range value.(*Route).Path {
					if key.(string) == path {
						exist = true
						break
					}
				}
				if !exist {
					t.delPath(key.(string), logger)
				}
			}
			return true
		})

		value.(*Route).SwapSign(logger)
		return true
	})
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
	if len(t.Path) == 0 || t.config == nil {
		return
	}

	for i := 0; i < len(t.Backs); i++ {
		t.Backs[i].route = t
		if p, ok := t.backMap.Load(t.Backs[i].Id()); !ok {
			logger.Info(`I:`, fmt.Sprintf("%v > %v > %v", t.config.Addr, t.Path, t.Backs[i].Name))
			t.backMap.Store(t.Backs[i].Id(), &t.Backs[i])
		} else if p.(*Back) != &t.Backs[i] {
			logger.Info(`I:`, fmt.Sprintf("%v > %v ~ %v", t.config.Addr, t.Path, t.Backs[i].Name))
		}
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
			logger.Info(`I:`, fmt.Sprintf("%v > %v x %v", t.config.Addr, t.Path, key))
			t.backMap.Delete(key)
		} else {
			value.(*Back).SwapSign(logger)
		}
		return true
	})
}

func (t *Route) FiliterBackByRequest(r *http.Request) []*Back {
	var backLink []*Back
	var (
		furi *unique.Handle[string]
		fher *unique.Handle[string]
	)
	for i := range t.Backs {

		urip := t.Backs[i].getFiliterReqUri()
		if (furi != nil || fher != nil) && &urip.Id != furi {
			continue
		}
		if ok, e := urip.Match(r); !ok || e != nil {
			continue
		}

		herp := t.Backs[i].getFiliterReqHeader()
		if (furi != nil || fher != nil) && &urip.Id != furi {
			continue
		}
		if ok, e := herp.Match(r.Header); !ok || e != nil {
			continue
		}

		if !t.Backs[i].AlwaysUp && t.Backs[i].Weight == 0 {
			continue
		}

		furi = &urip.Id
		fher = &herp.Id

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

func (t *Back) getProxy() string {
	if t.Proxy == "" {
		return t.route.Proxy
	}
	return t.Proxy
}
func (t *Back) getSplicing() int {
	if t.Splicing == 0 {
		return t.route.Splicing
	}
	return t.Splicing
}
func (t *Back) getPathAdd() bool {
	return t.route.PathAdd || t.PathAdd
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
func (t *Back) getDealerResBody() []dealer.Body {
	return append(t.route.Dealer.ResBody, t.Dealer.ResBody...)
}

func (t *Back) Id() string {
	return t.Name
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
	PathAdd            bool            `json:"pathAdd"`
	ErrToSec           float64         `json:"errToSec"`
	Splicing           int             `json:"splicing"`
	ErrBanSec          int             `json:"errBanSec"`
	InsecureSkipVerify bool            `json:"insecureSkipVerify"`
	VerifyPeerCer      string          `json:"verifyPeerCer"`
	Proxy              string          `json:"proxy"`
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
