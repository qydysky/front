package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	pfront "github.com/qydysky/front"
	pctx "github.com/qydysky/part/ctx"
	pfile "github.com/qydysky/part/file"
	plog "github.com/qydysky/part/log"
	reqf "github.com/qydysky/part/reqf"
	psys "github.com/qydysky/part/sys"
	pweb "github.com/qydysky/part/web"
)

func main() {
	// 保持唤醒
	defer (psys.Sys().PreventSleep()).Done()

	// 获取config路径
	var (
		configP      = flag.String("c", "main.json", "config")
		logFile      = flag.String("logFile", "", "logFile, defalut no log file")
		adminPort    = flag.Int("adminPort", 0, "adminPort, eg:10908")
		adminPath    = flag.String("adminPath", "", "adminPath, eg:/123/12/")
		reload       = flag.Bool("reload", false, "reload, when adminPort/adminPath set")
		restart      = flag.Bool("restart", false, "restart, when adminPort/adminPath set")
		stop         = flag.Bool("stop", false, "stop, when adminPort/adminPath set")
		noLog        = flag.Bool("noLog", false, "noLog")
		noDebugLog   = flag.Bool("noDebugLog", false, "noDebugLog")
		noAutoReload = flag.Bool("noAutoReload", false, "noAutoReload")
	)
	flag.Parse()

	// ctrl+c退出
	var interrupt = make(chan os.Signal, 2)
	signal.Notify(interrupt, os.Interrupt)

	for exit := false; !exit; {
		// 日志初始化
		logger := plog.New(plog.Config{
			Stdout: true,
			File:   *logFile,
			Prefix_string: map[string]struct{}{
				`T:`: plog.On,
				`I:`: plog.On,
				`W:`: plog.On,
				`E:`: plog.On,
			},
		}).Base(time.Now().Format("20060102150405>"))

		if *noLog {
			delete(logger.Config.Prefix_string, `E:`)
			delete(logger.Config.Prefix_string, `W:`)
			delete(logger.Config.Prefix_string, `I:`)
			delete(logger.Config.Prefix_string, `T:`)
		}

		if *noDebugLog {
			logger.L(`I:`, "关闭输出debug")
			delete(logger.Config.Prefix_string, `T:`)
		}

		// 根ctx
		ctx, cancle := pctx.WithWait(context.Background(), 0, time.Minute*2)

		// 获取config
		configS := []pfront.Config{}
		configF := pfile.New(*configP, 0, true)
		if !configF.IsExist() {
			logger.L(`E:`, "配置不存在")
			return
		}

		var (
			adminCancle = func() {}
			adminSign   = make(chan string, 1)
		)
		if *adminPort > 0 && len(*adminPath) > 3 && strings.HasPrefix(*adminPath, "/") && strings.HasPrefix(*adminPath, "/") {
			reloadPath := fmt.Sprintf("http://127.0.0.1:%d%sreload", *adminPort, *adminPath)
			restartPath := fmt.Sprintf("http://127.0.0.1:%d%srestart", *adminPort, *adminPath)
			stopPath := fmt.Sprintf("http://127.0.0.1:%d%sstop", *adminPort, *adminPath)
			if *reload {
				r := reqf.New()
				if e := r.Reqf(reqf.Rval{
					Url: reloadPath,
				}); e != nil {
					logger.L(`E:`, "reload", e)
				} else {
					logger.L(`I:`, "reload", string(r.Respon))
				}
				return
			}

			if *stop {
				r := reqf.New()
				if e := r.Reqf(reqf.Rval{
					Url: stopPath,
				}); e != nil {
					logger.L(`E:`, "stop", e)
				} else {
					logger.L(`I:`, "stop", string(r.Respon))
				}
				return
			}

			if *restart {
				r := reqf.New()
				if e := r.Reqf(reqf.Rval{
					Url: restartPath,
				}); e != nil {
					logger.L(`E:`, "restart", e)
				} else {
					logger.L(`I:`, "restart", string(r.Respon))
				}
				return
			}

			webPath := &pweb.WebPath{}
			webPath.Store(*adminPath+`reload`, func(w http.ResponseWriter, r *http.Request) {
				if e := pfront.Load(ctx, configF, &configS, logger); e != nil {
					_, _ = w.Write([]byte("err:" + e.Error()))
				} else {
					_, _ = w.Write([]byte("ok"))
				}
			})
			webPath.Store(*adminPath+`restart`, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
				adminSign <- "restart"
			})
			webPath.Store(*adminPath+`stop`, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
				adminSign <- "stop"
			})

			var hasErr = false
			timer := time.NewTicker(time.Millisecond * 100)
			defer timer.Stop()

			for {
				if adminSer, err := pweb.NewSyncMapNoPanic(&http.Server{
					Addr: fmt.Sprintf("127.0.0.1:%d", *adminPort),
				}, webPath); err == nil {
					logger.L(`I:`, "重载端口", reloadPath)
					logger.L(`I:`, "重起端口", restartPath)
					logger.L(`I:`, "停止端口", stopPath)
					adminCancle = func() { adminSer.Shutdown(ctx) }
					break
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

		logger.L(`I:`, "启动")
		// 加载配置
		if !*noAutoReload {
			if e := pfront.LoadPeriod(ctx, configF, &configS, logger); e != nil {
				return
			}
		} else if e := pfront.Load(ctx, configF, &configS, logger); e != nil {
			return
		}

		for i := 0; i < len(configS); i++ {
			if e, runf := configS[i].Run(ctx, logger); e != nil {
				return
			} else {
				go runf()
			}
		}

		select {
		case <-interrupt:
			exit = true
		case s := <-adminSign:
			if s == "stop" {
				exit = true
			}
		case <-ctx.Done():
		}

		logger.L(`I:`, "退出中")
		configF.Close()
		adminCancle()

		if e := cancle(); errors.Is(e, pctx.ErrWaitTo) {
			logger.L(`E:`, "退出超时")
		} else {
			logger.L(`I:`, "退出")
		}
	}
}
