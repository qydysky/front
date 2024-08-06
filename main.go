package front

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	_ "unsafe"

	"github.com/qydysky/front/dealer"
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
	var oldBufMd5 string

	if bufMd5, e := loadConfig(ctx, buf, configF, configS, logger); e != nil {
		logger.Error(`E:`, "配置加载", e)
		return e
	} else {
		oldBufMd5 = bufMd5
	}

	logger.Info(`I:`, "配置更新", oldBufMd5[:5])

	// 定时加载config
	go func() {
		ctx1, done1 := pctx.WaitCtx(ctx)
		defer done1()
		for {
			select {
			case <-time.After(time.Second * 5):
				if bufMd5, e := loadConfig(ctx, buf, configF, configS, logger); e != nil {
					logger.Error(`E:`, "配置加载", e)
				} else if bufMd5 != oldBufMd5 {
					oldBufMd5 = bufMd5
					logger.Info(`I:`, "配置更新", oldBufMd5[:5])
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
		`/`: func(w http.ResponseWriter, r *http.Request) {
			if strings.ToLower((r.Header.Get("Upgrade"))) == "websocket" {
				conn, _ := Upgrade(w, r, http.Header{
					"Upgrade":              []string{"websocket"},
					"Connection":           []string{"upgrade"},
					"Sec-Websocket-Accept": []string{computeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))},
				})
				conn.Close()
			} else {
				_, _ = io.Copy(io.Discard, r.Body)
				r.Body.Close()
				_, _ = w.Write([]byte("ok"))
			}
		},
	})
	<-ctx1.Done()
}

func loadConfig(ctx context.Context, buf []byte, configF File, configS *[]Config, logger Logger) (md5k string, e error) {
	// defer func() {
	// 	if err := recover(); err != nil {
	// 		logger.Error(`E:`, err)
	// 		e = errors.New("read panic")
	// 	}
	// }()
	if i, e := configF.Read(buf); e != nil && !errors.Is(e, io.EOF) {
		return "", e
	} else if i == cap(buf) {
		return "", errors.New(`buf full`)
	} else if !json.Valid(buf[:i]) {
		return "", errors.New(`json inValid`)
	} else {
		w := md5.New()
		w.Write(buf[:i])
		md5k = fmt.Sprintf("%x", w.Sum(nil))

		if e := json.Unmarshal(buf[:i], configS); e != nil {
			return md5k, e
		}
		for i := 0; i < len(*configS); i++ {
			(*configS)[i].lock.Lock()
			(*configS)[i].SwapSign(ctx, logger)
			(*configS)[i].lock.Unlock()
		}
	}
	return md5k, nil
}

func dealUri(s string, app []dealer.UriDealer) (t string) {
	t = s
	for _, v := range app {
		switch v.Action {
		case `replace`:
			t = regexp.MustCompile(v.MatchExp).ReplaceAllString(t, v.Value)
		default:
		}
	}
	fmt.Println(t, len(app))
	return
}

func copyHeader(s, t http.Header, app []dealer.HeaderDealer) error {
	sm := (map[string][]string)(s)
	tm := (map[string][]string)(t)
	for k, v := range sm {
		if strings.ToLower(k) == "origin" {
			continue
		}
		if strings.ToLower(k) == "set-cookie" {
			cookies := strings.Split(v[0], ";")
			for k, v := range cookies {
				if strings.Contains(strings.ToLower(v), "domain=") {
					cookies = append(cookies[:k], cookies[k+1:]...)
					break
				}
			}
			tm[k] = []string{strings.Join(cookies, ";")}
		} else {
			tm[k] = v
		}
	}
	for _, v := range app {
		switch v.Action {
		case `replace`:
			if va := t.Get(v.Key); va != "" {
				t.Set(v.Key, regexp.MustCompile(v.MatchExp).ReplaceAllString(va, v.Value))
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

var cookie = fmt.Sprintf("%p", &struct{}{})
var header = "X-Front-"
var (
	ErrRedirect        = errors.New("ErrRedirect")
	ErrNoHttp          = errors.New("ErrNoHttp")
	ErrNoWs            = errors.New("ErrNoWs")
	ErrCopy            = errors.New("ErrCopy")
	ErrReqCreFail      = errors.New("ErrReqCreFail")
	ErrReqDoFail       = errors.New("ErrReqDoFail")
	ErrResDoFail       = errors.New("ErrResDoFail")
	ErrResFail         = errors.New("ErrResFail")
	ErrResTO           = errors.New("ErrResTO")
	ErrUriTooLong      = errors.New("ErrUriTooLong")
	ErrPatherCheckFail = errors.New("ErrPatherCheckFail")
	ErrHeaderCheckFail = errors.New("ErrHeaderCheckFail")
	ErrBodyCheckFail   = errors.New("ErrBodyCheckFail")
	ErrAllBacksFail    = errors.New("ErrAllBacksFail")
	ErrBackFail        = errors.New("ErrBackFail")
	ErrNoRoute         = errors.New("ErrNoRoute")
	ErrDealReqUri      = errors.New("ErrDealReqUri")
	ErrDealReqHeader   = errors.New("ErrDealReqHeader")
	ErrDealResHeader   = errors.New("ErrDealResHeader")
	ErrCerVerify       = errors.New("ErrCerVerify")
)
