package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	pfront "github.com/qydysky/front"
	pca "github.com/qydysky/part/crypto/asymmetric"
	pcs "github.com/qydysky/part/crypto/symmetric"
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
		genKey       = flag.Bool("genKey", false, "gen new pub.pem and pri.pem")
		decrypt      = flag.String("decrypt", "", "decrypt with pri.pem")
		encrypt      = flag.String("encrypt", "", "encrypt with pub.pem")
	)
	flag.Parse()

	if *genKey {
		if pri, pub, e := pca.MlkemF.NewKey(); e != nil {
			panic(e)
		} else {
			fmt.Println("pub.pem(for -encrypt):")
			fmt.Println(string(pem.EncodeToMemory(pub)))
			fmt.Println("pri.pem(for -decrypt)")
			fmt.Println(string(pem.EncodeToMemory(pri)))
			os.Exit(0)
		}
	}
	if *decrypt != "" {
		if data, err := fileLoad(*decrypt); err != nil {
			os.Stderr.Write([]byte(err.Error()))
			return
		} else {
			priKey, _ := pem.Decode(data)
			defer clear(priKey.Bytes)

			if dec, e := pca.ChoseAsymmetricByPem(priKey).Decrypt(priKey); e != nil {
				os.Stderr.Write([]byte(e.Error()))
				return
			} else {
				buf := bytes.NewBuffer([]byte{})
				io.Copy(buf, os.Stdin)
				b, ext := pca.Unpack(buf.Bytes())
				defer clear(b)
				defer clear(ext)

				if s, e := dec(pcs.Chacha20poly1305F, b, ext); e != nil {
					os.Stderr.Write([]byte(e.Error()))
				} else {
					os.Stdout.Write(s)
				}
				return
			}
		}
	}
	if *encrypt != "" {
		if data, err := fileLoad(*encrypt); err != nil {
			os.Stderr.Write([]byte(err.Error()))
			return
		} else {
			pubKey, _ := pem.Decode(data)
			defer clear(pubKey.Bytes)

			if enc, e := pca.ChoseAsymmetricByPem(pubKey).Encrypt(pubKey); e != nil {
				os.Stderr.Write([]byte(e.Error()))
				return
			} else {
				buf := bytes.NewBuffer([]byte{})
				io.Copy(buf, os.Stdin)
				if b, ext, e := enc(pcs.Chacha20poly1305F, buf.Bytes()); e != nil {
					os.Stderr.Write([]byte(e.Error()))
					return
				} else {
					os.Stdout.Write(pca.Pack(b, ext))
				}
				return
			}
		}
	}

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
		if *adminPort > 0 {
			if len(*adminPath) <= 3 || !strings.HasPrefix(*adminPath, "/") || !strings.HasPrefix(*adminPath, "/") {
				logger.L(`E:`, "adminPath 必须大于3字符长度并以/开头及结尾")
				return
			}
			reloadPath := fmt.Sprintf("http://127.0.0.1:%d%sreload", *adminPort, *adminPath)
			restartPath := fmt.Sprintf("http://127.0.0.1:%d%srestart", *adminPort, *adminPath)
			stopPath := fmt.Sprintf("http://127.0.0.1:%d%sstop", *adminPort, *adminPath)
			configPath := fmt.Sprintf("http://127.0.0.1:%d%sconfig", *adminPort, *adminPath)
			if *reload {
				r := reqf.New()
				if e := r.Reqf(reqf.Rval{
					Url: reloadPath,
				}); e != nil {
					logger.L(`E:`, "reload", e)
				} else {
					r.Respon(func(b []byte) error {
						logger.L(`I:`, "reload", string(b))
						return nil
					})
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
					r.Respon(func(b []byte) error {
						logger.L(`I:`, "stop", string(b))
						return nil
					})
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
					r.Respon(func(b []byte) error {
						logger.L(`I:`, "restart", string(b))
						return nil
					})
				}
				return
			}

			webPath := &pweb.WebPath{}
			webPath.Store(*adminPath, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("ok"))
			})
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
			webPath.Store(*adminPath+`config`, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(`Content-Type`, `application/json; charset=utf-8`)
				if b, e := json.MarshalIndent(&configS, "", "\t"); e != nil {
					_, _ = w.Write([]byte(`{"err":"` + e.Error() + `"}`))
				} else {
					_, _ = w.Write(b)
				}
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
					logger.L(`I:`, "运行信息", configPath)
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
			go configS[i].Run(ctx, logger)()
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

func fileLoad(path string) (data []byte, err error) {
	fileObject, e := os.OpenFile(path, os.O_RDONLY, 0644)
	if e != nil {
		err = e
		return
	}
	defer fileObject.Close()
	data, e = io.ReadAll(fileObject)
	if e != nil {
		err = e
		return
	}
	return
}
