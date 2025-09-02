package front

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"regexp"
	"strings"
	"time"
	_ "unsafe"

	"slices"

	"github.com/dustin/go-humanize"
	"github.com/qydysky/front/dealer"
	utils "github.com/qydysky/front/utils"
	pctx "github.com/qydysky/part/ctx"
	pfile "github.com/qydysky/part/file"
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

// 加载
func LoadPeriod(ctx context.Context, configF *pfile.File, configS *[]Config, logger Logger) error {
	if e := Load(ctx, configF, configS, logger); e != nil {
		return e
	}

	// 定时加载config
	go func() {
		ctx1, done1 := pctx.WaitCtx(ctx)
		defer done1()
		for {
			select {
			case <-time.After(time.Second * 5):
				_ = Load(ctx, configF, configS, logger)
			case <-ctx1.Done():
				return
			}
		}
	}()
	return nil
}

// 加载
func Load(ctx context.Context, configF *pfile.File, configS *[]Config, logger Logger) error {
	var buf, _ = configF.ReadAll(humanize.KByte, humanize.MByte)
	if e := loadConfig(ctx, buf, configS, logger); e != nil {
		return e
	}
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
					"Sec-Websocket-Accept": []string{utils.ComputeAcceptKey(r.Header.Get("Sec-WebSocket-Key"))},
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

func loadConfig(ctx context.Context, buf []byte, configS *[]Config, logger Logger) (e error) {
	// defer func() {
	// 	if err := recover(); err != nil {
	// 		logger.Error(`E:`, err)
	// 		e = errors.New("read panic")
	// 	}
	// }()
	if !json.Valid(buf) {
		return errors.New(`json inValid`)
	} else {
		if e := json.Unmarshal(buf, configS); e != nil {
			return e
		}
		for i := 0; i < len(*configS); i++ {
			(*configS)[i].lock.Lock()
			(*configS)[i].SwapSign(ctx, logger)
			(*configS)[i].lock.Unlock()
		}
	}
	return
}

func dealUri(s string, app iter.Seq[dealer.UriDealer]) (t string) {
	t = s
	for v := range app {
		switch v.Action {
		case `replace`:
			t = regexp.MustCompile(v.MatchExp).ReplaceAllString(t, v.Value)
		default:
		}
	}
	return
}

func copyHeader(env map[string]string, s, t http.Header, app iter.Seq[dealer.HeaderDealer]) {
	sm := (map[string][]string)(s)
	tm := (map[string][]string)(t)
	for k, v := range sm {
		if strings.ToLower(k) == "origin" || strings.ToLower(k) == "content-length" {
			continue
		}
		if strings.ToLower(k) == "set-cookie" {
			for _, cookie := range v {
				cookieSlice := strings.Split(cookie, ";")
				for cookieK, cookieV := range cookieSlice {
					if strings.HasPrefix(strings.TrimSpace(strings.ToLower(cookieV)), "domain=") {
						cookieSlice = slices.Delete(cookieSlice, cookieK, cookieK+1)
					}
				}
				tm[k] = append(tm[k], strings.Join(cookieSlice, ";"))
			}
		} else {
			tm[k] = append(tm[k], v...)
		}
	}

	for v := range app {
		switch v.Action {
		case `replace`:
			if va := t.Get(v.Key); va != "" {
				t.Set(v.Key, regexp.MustCompile(v.MatchExp).ReplaceAllString(va, getEnv(env, v.Value)))
			}
		case `set`:
			t.Set(v.Key, getEnv(env, v.Value))
		case `add`:
			t.Add(v.Key, getEnv(env, v.Value))
		case `del`:
			t.Del(v.Key)
		default:
		}
	}
}

func getEnv(m map[string]string, val string) string {
	if len(val) == 0 || val[0] != '$' {
		return val
	} else if v, ok := m[val]; ok {
		return v
	} else {
		return val
	}
}

func setEnvIfNot(m map[string]string, key, val string) {
	if v, ok := m[key]; !ok || v == "" {
		m[key] = val
	}
}

func setEnv(m map[string]string, key, val string) {
	m[key] = val
}

// var header = "X-Front-"
var cookie = fmt.Sprintf("_psign_%p_%s", &struct{}{}, time.Now().Format("20060102150405"))
var (
	ErrRedirect          = errors.New("ErrRedirect")
	ErrNoHttp            = errors.New("ErrNoHttp")
	ErrNoWs              = errors.New("ErrNoWs")
	ErrCopy              = errors.New("ErrCopy")
	ErrReqReBodyFail     = errors.New("ErrReqReBodyFail")
	ErrReqReBodyFull     = errors.New("ErrReqReBodyFull")
	ErrReqReBodyOverflow = errors.New("ErrReqReBodyOverflow")
	ErrReqRetry          = errors.New("ErrReqRetry")
	ErrReqCreFail        = errors.New("ErrReqCreFail")
	ErrReqDoFail         = errors.New("ErrReqDoFail")
	ErrResDoFail         = errors.New("ErrResDoFail")
	ErrResFail           = errors.New("ErrResFail")
	ErrResTO             = errors.New("ErrResTO")
	ErrUriTooLong        = errors.New("ErrUriTooLong")
	ErrCheckFail         = errors.New("ErrCheckFail")
	ErrPatherCheckFail   = errors.New("ErrPatherCheckFail")
	ErrHeaderCheckFail   = errors.New("ErrHeaderCheckFail")
	ErrBodyCheckFail     = errors.New("ErrBodyCheckFail")
	ErrAllBacksFail      = errors.New("ErrAllBacksFail")
	ErrBackFail          = errors.New("ErrBackFail")
	ErrNoRoute           = errors.New("ErrNoRoute")
	ErrDealReqUri        = errors.New("ErrDealReqUri")
	ErrDealReqHeader     = errors.New("ErrDealReqHeader")
	ErrDealResHeader     = errors.New("ErrDealResHeader")
	ErrCerVerify         = errors.New("ErrCerVerify")
)
