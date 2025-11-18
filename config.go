package front

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
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
	pe "github.com/qydysky/part/errors"
	pfile "github.com/qydysky/part/file"
	pio "github.com/qydysky/part/io"
	reqf "github.com/qydysky/part/reqf"
	pslice "github.com/qydysky/part/slice"
	psync "github.com/qydysky/part/sync"
	pweb "github.com/qydysky/part/web"
)

var ErrDuplicatePath = errors.New(`ErrDuplicatePath`)

type Config struct {
	lock sync.RWMutex `json:"-"`
	Addr string       `json:"addr"`
	TLS  struct {
		Pub     string   `json:"pub,omitempty"`
		Key     string   `json:"key,omitempty"`
		Decrypt []string `json:"decrypt,omitempty"`
	} `json:"tls"`
	RetryBlocks  Blocks                      `json:"retryBlocks"`
	RetryBlocksI pslice.BlocksI[byte]        `json:"-"`
	MatchRule    string                      `json:"matchRule"`
	CopyBlocks   Blocks                      `json:"copyBlocks"`
	BlocksI      pslice.BlocksI[byte]        `json:"-"`
	webpath      *pweb.WebPath               `json:"-"`
	routeMap     psync.MapG[string, *Pather] `json:"-"`
	Routes       []Route                     `json:"routes"`

	ReqIdLoop int           `json:"reqIdLoop"`
	reqId     atomic.Uint32 `json:"-"`
}

type Blocks struct {
	Size string `json:"size,omitempty"`
	size int    `json:"-"`
	Num  int    `json:"num,omitempty"`
}

func (t *Config) Run(ctx context.Context, logger Logger) (run func()) {

	ctx, done := pctx.WithWait(ctx, 0, time.Minute)

	httpSer := http.Server{
		Addr:        t.Addr,
		BaseContext: func(l net.Listener) context.Context { return ctx },
	}
	if t.TLS.Key != "" && t.TLS.Pub != "" {
		var (
			pub           []byte
			pri           []byte
			errPub        error
			errPri        error
			errPubDecrypt error
			errPriDecrypt error
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
			r.Respon(func(b []byte) error {
				pub = b
				return nil
			})
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
			r.Respon(func(b []byte) error {
				pri = b
				return nil
			})
		}
		if len(pub) > 0 && len(t.TLS.Decrypt) > 0 {
			var buf = bytes.NewBuffer([]byte{})
			cmd := exec.CommandContext(ctx, t.TLS.Decrypt[0], t.TLS.Decrypt[1:]...)
			cmd.Stderr = os.Stdout
			cmd.Stdout = buf
			cmd.Stdin = bytes.NewReader(pub)
			errPubDecrypt = cmd.Run()
			pub = buf.Bytes()
		}
		if len(pri) > 0 && len(t.TLS.Decrypt) > 0 {
			var buf = bytes.NewBuffer([]byte{})
			cmd := exec.CommandContext(ctx, t.TLS.Decrypt[0], t.TLS.Decrypt[1:]...)
			cmd.Stderr = os.Stdout
			cmd.Stdout = buf
			cmd.Stdin = bytes.NewReader(pri)
			errPriDecrypt = cmd.Run()
			pri = buf.Bytes()
		}
		if errPub != nil || errPri != nil || errPubDecrypt != nil || errPriDecrypt != nil {
			logger.Error(`E:`, fmt.Sprintf("%v errPub(%v) errPri(%v) errPubDecrypt(%v) errPriDecrypt(%v)", t.Addr, errPub, errPri, errPubDecrypt, errPriDecrypt))
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

	t.webpath = &pweb.WebPath{}

	t.SwapSign(ctx, logger)

	return func() {
		shutdownf := t.startServer(logger, &httpSer)
		logger.Info(`I:`, fmt.Sprintf("%v running", t.Addr))
		<-ctx.Done()
		shutdownf()
		logger.Info(`I:`, fmt.Sprintf("%v shutdown", t.Addr))
		_ = done()
	}
}

func (t *Config) startServer(logger Logger, conf *http.Server) (shutdown func(ctx ...context.Context)) {
	shutdown = func(ctx ...context.Context) {}

	timer := time.NewTicker(time.Millisecond * 100)
	defer timer.Stop()

	var matchFunc func(path string) (func(w http.ResponseWriter, r *http.Request), bool)
	switch t.MatchRule {
	case `all`:
		matchFunc = t.webpath.Load
	case `prefix`:
		fallthrough
	default:
		matchFunc = t.webpath.LoadPerfix
	}

	var hasErr = false
	for {
		web, err := pweb.NewSyncMapNoPanic(conf, t.webpath, matchFunc)

		shutdown = web.Shutdown

		if err != nil {
			if !hasErr {
				hasErr = true
				logger.Warn(`W:`, fmt.Sprintf("%v. Retry...", err))
			}
			<-timer.C
		} else {
			return
		}
	}
}

type reqBufS struct {
	data       []byte
	maxCap     int
	allowReuse bool
	used       bool
	allReaded  bool
}

func (t *Config) SwapSign(ctx context.Context, logger Logger) {
	// add new route
	for k := 0; k < len(t.Routes); k++ {
		route := &t.Routes[k]
		route.config = t
		for _, routePath := range route.Path {
			pather, _ := t.routeMap.LoadOrStore(routePath, NewPather())
			pather.Add(route)

			route.SwapSign(logger)
			t.webpath.StoreIfNotExist(routePath, func(w http.ResponseWriter, r *http.Request) {
				reqId := t.reqId.Add(1)
				if reqId >= uint32(t.ReqIdLoop) {
					t.reqId.Store(0)
				}

				var (
					logFormat = "%d %v %v%v %v %v"
				)

				if len(r.RequestURI) > 8000 {
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.Addr, routePath, "BLOCK", ErrUriTooLong))
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				if pather, ok := t.routeMap.Load(routePath); ok {

					var (
						reqBuf  *reqBufS
						putBack = func() {}
						err     error
					)
					if t.RetryBlocksI != nil {
						reqBuf = &reqBufS{
							maxCap:     t.RetryBlocks.size,
							allowReuse: true,
						}
						reqBuf.data, putBack, err = t.RetryBlocksI.Get()
						defer putBack()
						if err != nil {
							reqBuf = nil
						}
					}

					for v := range pather.Range() {
						err = v.WR(reqId, routePath, logger, reqBuf, w, r)
						if err == nil {
							break
						}
						if reqBuf != nil && !reqBuf.allowReuse {
							break
						}
					}
					switch {
					case err == nil:
						return
					case errors.Is(err, context.DeadlineExceeded):
						return
					case errors.Is(err, ErrHeaderCheckFail), errors.Is(err, ErrBodyCheckFail), errors.Is(err, ErrCheckFail), errors.Is(err, ErrNoRoute):
						w.WriteHeader(http.StatusForbidden)
					default:
						w.WriteHeader(http.StatusNotFound)
					}
				}
			})
		}
	}

	t.routeMap.Range(func(routePath string, pather *Pather) bool {
		for routeP := range pather.Range() {
			var exist bool
			for k := 0; !exist && k < len(t.Routes); k++ {
				exist = routeP == &t.Routes[k]
			}
			if !exist {
				pather.Del(routeP)
			}
		}
		if pather.Size() == 0 {
			t.webpath.Delete(routePath)
			t.routeMap.CompareAndDelete(routePath, pather)
		}
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
	Name   string   `json:"name"`
	config *Config  `json:"-"`
	Path   []string `json:"path"`

	RollRule string `json:"rollRule,omitempty"`
	AlwaysUp bool   `json:"alwaysUp"`
	Setting

	backMap sync.Map `json:"-"`
	Backs   []Back   `json:"backs"`
}

func (t *Route) Id() string {
	return fmt.Sprintf("%p", t)
}

func (t *Route) getFiliters() (f iter.Seq[*filiter.Filiter]) {
	return func(yield func(*filiter.Filiter) bool) {
		for i := 0; i < len(t.Filiters); i++ {
			if !yield(t.Filiters[i]) {
				return
			}
		}
	}
}

func (t *Route) SwapSign(logger Logger) {
	if len(t.Path) == 0 || t.config == nil {
		return
	}

	for i := 0; i < len(t.Backs); i++ {
		t.Backs[i].route = t
		if p, ok := t.backMap.Load(t.Backs[i].Id()); !ok {
			logger.Info(`I:`, fmt.Sprintf("%v > %v > %v", t.config.Addr, t.Name, t.Backs[i].Name))
			t.backMap.Store(t.Backs[i].Id(), &t.Backs[i])
		} else if p.(*Back) != &t.Backs[i] {
			logger.Info(`I:`, fmt.Sprintf("%v > %v ~ %v", t.config.Addr, t.Name, t.Backs[i].Name))
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
			logger.Info(`I:`, fmt.Sprintf("%v > %v x %v", t.config.Addr, t.Name, key))
			t.backMap.Delete(key)
		} else {
			value.(*Back).SwapSign(logger)
		}
		return true
	})
}

func (t *Route) FiliterBackByRequest(r *http.Request) []*Back {
	var backLink []*Back
	var passFiliter *unique.Handle[string]
	for i := range t.Backs {

		var noPassFiliter bool = passFiliter != nil
		for filiter := range t.Backs[i].getFiliters() {
			noPassFiliter = true
			if passFiliter != nil && filiter.Id() != passFiliter {
				continue
			}
			if ok, e := filiter.ReqAddr.Match(r); !ok || e != nil {
				continue
			}
			if ok, e := filiter.ReqHost.Match(r); !ok || e != nil {
				continue
			}
			if ok, e := filiter.ReqUri.Match(r); !ok || e != nil {
				continue
			}
			if ok, e := filiter.ReqHeader.Match(r.Header); !ok || e != nil {
				continue
			}
			passFiliter = filiter.Id()
			noPassFiliter = false
			break
		}
		if noPassFiliter {
			continue
		}

		backLink = append(backLink, &t.Backs[i])
	}

	return backLink
}

func (t *Route) WR(reqId uint32, routePath string, logger Logger, reqBuf *reqBufS, w http.ResponseWriter, r *http.Request) (err error) {
	var (
		logFormat         = "%d %v %v%v > %v %v %v"
		logFormatWithName = "%v %v %v%v > %v > %v %v %v"
	)

	var noPassFiliter bool
	for filiter := range t.getFiliters() {
		noPassFiliter = true
		if ok, e := filiter.ReqAddr.Match(r); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
		} else if !ok {
			continue
		}

		if ok, e := filiter.ReqHost.Match(r); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
		} else if !ok {
			continue
		}

		if ok, e := filiter.ReqUri.Match(r); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
		} else if !ok {
			continue
		}

		if ok, e := filiter.ReqHeader.Match(r.Header); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
		} else if !ok {
			continue
		}

		if ok, e := filiter.ReqBody.Match(r); e != nil {
			logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
		} else if !ok {
			continue
		}
		noPassFiliter = false
		break
	}
	if noPassFiliter {
		return ErrCheckFail
	}

	var (
		backIs    []*Back
		backEqual = func(a, b *Back) bool {
			return a == b
		}
	)

	{
		if val, e := r.Cookie(cookie); e == nil {
			if backP, aok := t.backMap.Load(val.Value); aok {
				var noPassFiliter bool
				for filiter := range backP.(*Back).getFiliters() {
					noPassFiliter = true
					if ok, e := filiter.ReqAddr.Match(r); !ok || e != nil {
						continue
					}
					if ok, e := filiter.ReqHost.Match(r); !ok || e != nil {
						continue
					}
					if ok, e := filiter.ReqUri.Match(r); !ok || e != nil {
						continue
					}
					if ok, e := filiter.ReqHeader.Match(r.Header); !ok || e != nil {
						continue
					}
					noPassFiliter = false
					break
				}
				if !noPassFiliter {
					backIs = addIfNotExsit(backIs, backEqual, backP.(*Back))
				}
			}
		}

		var splicingC = len(backIs)

		backIs = addIfNotExsit(backIs, backEqual, t.FiliterBackByRequest(r)...)

		if f, ok := rollRuleMap[t.RollRule]; ok {
			f(backIs[splicingC:])
		} else {
			rand_Shuffle(backIs[splicingC:])
		}
	}

	if len(backIs) == 0 {
		return ErrNoRoute
	} else {
		var (
			needUp   int
			disableC uint
		)

		for i := 0; needUp != -1 && i < len(backIs); i++ {
			ul := backIs[i].lock.RLock()
			if backIs[i].UpT.Before(time.Now()) {
				needUp = -1
			} else {
				if c := backIs[i].DisableC; disableC == 0 || disableC > c {
					disableC = c
					needUp = i
				}
			}
			ul()
		}
		if needUp >= 0 && t.AlwaysUp {
			logger.Warn(`W:`, fmt.Sprintf(logFormatWithName, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, backIs[needUp].Name, "Err", ErrReUp))
			backIs[needUp].Enable()
		}
	}

	type reqDealer interface {
		Deal(ctx context.Context, reqId uint32, w http.ResponseWriter, r *http.Request, routePath string, chosenBack *Back, logger Logger, blocksi pslice.BlocksI[byte]) error
	}

	// repack
	var (
		reqContentLength string = r.Header.Get("Content-Length")
		delayBody        io.ReadCloser
	)
	if reqBuf != nil {
		if r.Body != nil && reqContentLength != "" {
			if n, e := strconv.Atoi(reqContentLength); e != nil {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
			} else if n > reqBuf.maxCap {
				logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", ErrReqReBodyOverflow))
			} else {
				reqBuf.used = true
				offset := 0
				for offset < cap(reqBuf.data) {
					n, e := r.Body.Read(reqBuf.data[offset:])
					offset += n
					if e != nil {
						if !errors.Is(e, io.EOF) {
							logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", e))
							w.WriteHeader(http.StatusBadRequest)
							return nil
						}
						reqBuf.allReaded = true
						break
					} else if n == 0 {
						break
					}
				}
				reqBuf.data = reqBuf.data[:offset]
				if !reqBuf.allReaded {
					reqBuf.allowReuse = false
					delayBody = r.Body
					logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", ErrReqReBodyFull))
				}
			}
		}
	}

	err = ErrAllBacksFail
	for _, backP := range backIs {
		if !backP.IsLive() {
			continue
		}

		backP.chosen()

		if reqBuf != nil && reqBuf.used {
			if !reqBuf.allReaded {
				r.Body = pio.RWC{
					R: io.MultiReader(bytes.NewBuffer(reqBuf.data), delayBody).Read,
					C: delayBody.Close,
				}
			} else {
				r.Body = io.NopCloser(bytes.NewBuffer(reqBuf.data))
			}
		}

		var (
			ctx    context.Context    = r.Context()
			cancle context.CancelFunc = func() {}
		)

		if backP.getCtxToSec() > 0 {
			ctx, cancle = context.WithTimeout(ctx, time.Second*time.Duration(backP.getCtxToSec()))
		}

		if backP.To == "" {
			err = component2.GetV3[reqDealer]("echo").Inter().Deal(ctx, reqId, w, r, routePath, backP, logger, t.config.BlocksI)
		} else if !strings.Contains(backP.To, "://") {
			err = component2.GetV3[reqDealer]("local").Inter().Deal(ctx, reqId, w, r, routePath, backP, logger, t.config.BlocksI)
		} else if strings.ToLower((r.Header.Get("Upgrade"))) == "websocket" {
			err = component2.GetV3[reqDealer]("ws").Inter().Deal(ctx, reqId, w, r, routePath, backP, logger, t.config.BlocksI)
		} else {
			err = component2.GetV3[reqDealer]("http").Inter().Deal(ctx, reqId, w, r, routePath, backP, logger, t.config.BlocksI)
		}

		cancle()

		if err == nil {
			// no err
			break
		}

		if errors.Is(err, context.Canceled) {
			break
		}

		if v, ok := err.(ErrCanRetry); !ok || !v.CanRetry {
			// some err can't retry
			break
		} else if reqContentLength != "" && reqBuf != nil && !reqBuf.allowReuse {
			// has body but buf no allow reuse
			break
		}

		logger.Debug(`T:`, fmt.Sprintf(logFormatWithName, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, backP.Name, "ErrCanRetry", pe.ErrorFormat(err, pe.ErrActionInLineFunc)))
	}

	if err != nil {
		logger.Warn(`W:`, fmt.Sprintf(logFormat, reqId, r.RemoteAddr, t.config.Addr, routePath, t.Name, "Err", pe.ErrorFormat(err, pe.ErrActionInLineFunc)))
	}
	return
}

type Back struct {
	route       *Route        `json:"-"`
	lock        psync.RWMutex `json:"-"`
	UpT         time.Time     `json:"upT"`
	LastChosenT time.Time     `json:"lastChosenT"`
	LastFailT   time.Time     `json:"lastFailT"`
	DisableC    uint          `json:"disableC"`
	DealingC    uint          `json:"dealingC"`
	ChosenC     uint          `json:"chosenC"`

	lastResDru time.Duration `json:"-"`

	Name   string `json:"name"`
	To     string `json:"to"`
	Weight uint   `json:"weight,string"`

	Setting
}

func BatchRLock(backs []*Back) iter.Seq2[int, *Back] {
	return func(yield func(int, *Back) bool) {
		var stop bool
		for k, v := range backs {
			ul := v.lock.RLock()
			stop = !yield(k, v)
			ul()
			if stop {
				break
			}
		}
	}
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
func (t *Back) getCtxToSec() float64 {
	if t.CtxToSec == 0 {
		return t.route.CtxToSec
	} else {
		return t.CtxToSec
	}
}
func (t *Back) getInsecureSkipVerify() bool {
	return t.route.InsecureSkipVerify || t.InsecureSkipVerify
}
func (t *Back) getVerifyPeerCer() (cer []byte, e error) {
	return t.verifyPeerCer, t.verifyPeerCerErr
}
func (t *Back) getFiliters() (f iter.Seq[*filiter.Filiter]) {
	return func(yield func(*filiter.Filiter) bool) {
		// for i := 0; i < len(t.route.Filiters); i++ {
		// 	if !yield(t.route.Filiters[i]) {
		// 		return
		// 	}
		// }
		for i := 0; i < len(t.Filiters); i++ {
			if !yield(t.Filiters[i]) {
				return
			}
		}
	}
}

// func (t *Back) getFiliterReqHeader() *filiter.Header {
// 	if !t.Filiter.ReqHeader.Valid() {
// 		return &t.route.Filiter.ReqHeader
// 	} else {
// 		return &t.Filiter.ReqHeader
// 	}
// }
// func (t *Back) getFiliterReqUri() *filiter.Uri {
// 	if !t.Filiter.ReqUri.Valid() {
// 		return &t.route.Filiter.ReqUri
// 	} else {
// 		return &t.Filiter.ReqUri
// 	}
// }
// func (t *Back) getFiliterResHeader() *filiter.Header {
// 	if !t.Filiter.ResHeader.Valid() {
// 		return &t.route.Filiter.ResHeader
// 	} else {
// 		return &t.Filiter.ResHeader
// 	}
// }

//	func (t *Back) getFiliterResBody() *filiter.Body {
//		if !t.Filiter.ReqBody.Valid() {
//			return &t.route.Filiter.ReqBody
//		} else {
//			return &t.Filiter.ReqBody
//		}
//	}
func (t *Back) getDealerReqUri() iter.Seq[dealer.UriDealer] {
	return func(yield func(dealer.UriDealer) bool) {
		for i := 0; i < len(t.Dealer.ReqUri); i++ {
			if !yield(t.Dealer.ReqUri[i]) {
				return
			}
		}
		for i := 0; i < len(t.route.Dealer.ReqUri); i++ {
			if !yield(t.route.Dealer.ReqUri[i]) {
				return
			}
		}
	}
}
func (t *Back) getDealerReqHeader() iter.Seq[dealer.HeaderDealer] {
	return func(yield func(dealer.HeaderDealer) bool) {
		for i := 0; i < len(t.Dealer.ReqHeader); i++ {
			if !yield(t.Dealer.ReqHeader[i]) {
				return
			}
		}
		for i := 0; i < len(t.route.Dealer.ReqHeader); i++ {
			if !yield(t.route.Dealer.ReqHeader[i]) {
				return
			}
		}
	}
}
func (t *Back) getDealerResHeader() iter.Seq[dealer.HeaderDealer] {
	return func(yield func(dealer.HeaderDealer) bool) {
		for i := 0; i < len(t.Dealer.ResHeader); i++ {
			if !yield(t.Dealer.ResHeader[i]) {
				return
			}
		}
		for i := 0; i < len(t.route.Dealer.ResHeader); i++ {
			if !yield(t.route.Dealer.ResHeader[i]) {
				return
			}
		}
	}
}
func (t *Back) getDealerResBody() iter.Seq[dealer.Body] {
	return func(yield func(dealer.Body) bool) {
		for i := 0; i < len(t.Dealer.ResBody); i++ {
			if !yield(t.Dealer.ResBody[i]) {
				return
			}
		}
		for i := 0; i < len(t.route.Dealer.ResBody); i++ {
			if !yield(t.route.Dealer.ResBody[i]) {
				return
			}
		}
	}
}
func (t *Back) getDealerResStatus(yieldNoBreak ...func()) iter.Seq[dealer.StatusDealer] {
	return func(yield func(dealer.StatusDealer) bool) {
		if t.Dealer.ResStatus.Valid() {
			if !yield(t.Dealer.ResStatus) {
				return
			}
		}
		if t.route.Dealer.ResStatus.Valid() {
			if !yield(t.route.Dealer.ResStatus) {
				return
			}
		}
		for _, v := range yieldNoBreak {
			v()
		}
	}
}

func (t *Back) Id() string {
	return fmt.Sprintf("%p", t)
}

func (t *Back) be(opT time.Time) {
	defer t.lock.Lock()()
	t.ChosenC += 1
	t.lastResDru = time.Since(opT)
	t.DealingC += 1
}

func (t *Back) ed() {
	defer t.lock.Lock()()
	t.DealingC -= 1
}

func (t *Back) chosen() {
	defer t.lock.Lock()()
	t.LastChosenT = time.Now()
}

func (t *Back) IsLive() bool {
	defer t.lock.RLock()()
	return t.UpT.Before(time.Now())
}

func (t *Back) Disable() {
	now := time.Now()
	defer t.lock.RLock()()
	t.DisableC += 1
	t.LastFailT = now
	if tmp := t.getErrBanSec(); tmp > 0 {
		t.UpT = now.Add(time.Second * time.Duration(tmp))
	}
}

func (t *Back) Enable() {
	defer t.lock.Lock()()
	t.UpT = time.Now()
}

type Setting struct {
	PathAdd            bool               `json:"pathAdd"`
	CtxToSec           float64            `json:"ctxToSec"`
	ErrToSec           float64            `json:"errToSec"`
	Splicing           int                `json:"splicing"`
	ErrBanSec          int                `json:"errBanSec"`
	InsecureSkipVerify bool               `json:"insecureSkipVerify"`
	VerifyPeerCer      string             `json:"verifyPeerCer,omitempty"`
	Proxy              string             `json:"proxy,omitempty"`
	Filiters           []*filiter.Filiter `json:"filiters,omitempty"`
	Dealer             dealer.Dealer      `json:"dealer,omitempty"`
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
