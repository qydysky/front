package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"slices"
	"time"

	pfront "github.com/qydysky/front"
	pctx "github.com/qydysky/part/ctx"
	pfile "github.com/qydysky/part/file"
	plog "github.com/qydysky/part/log"
	psys "github.com/qydysky/part/sys"
)

func main() {
	// 保持唤醒
	var stop = psys.Sys().PreventSleep()
	defer stop.Done()

	// 获取config路径
	configP := flag.String("c", "main.json", "config")
	testP := flag.Int("t", 0, "test port")
	_ = flag.Bool("q", false, "no log")
	_ = flag.Bool("dq", false, "no debug log")
	flag.Parse()

	// 日志初始化
	logger := plog.New(plog.Config{
		Stdout: true,
		Prefix_string: map[string]struct{}{
			`T:`: plog.On,
			`I:`: plog.On,
			`W:`: plog.On,
			`E:`: plog.On,
		},
	})

	if slices.Contains(os.Args[1:], "-q") {
		delete(logger.Config.Prefix_string, `E:`)
		delete(logger.Config.Prefix_string, `W:`)
		delete(logger.Config.Prefix_string, `I:`)
		delete(logger.Config.Prefix_string, `T:`)
	}

	if slices.Contains(os.Args[1:], "-dq") {
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
	defer configF.Close()

	var buf = make([]byte, 1<<16)

	// 加载配置
	if e := pfront.LoadPeriod(ctx, buf, configF, &configS, logger); e != nil {
		return
	}

	// 测试响应
	go pfront.Test(ctx, *testP, logger.Base("测试"))

	for i := 0; i < len(configS); i++ {
		go pfront.Run(ctx, &configS[i], logger.Base(configS[i].Addr))
	}

	// ctrl+c退出
	var interrupt = make(chan os.Signal, 2)
	signal.Notify(interrupt, os.Interrupt)
	<-interrupt
	logger.L(`I:`, "退出中,再次ctrl+c强制退出")
	go func() {
		<-interrupt
		os.Exit(1)
	}()
	if errors.Is(cancle(), pctx.ErrWaitTo) {
		logger.L(`E:`, "退出超时")
	}
}
