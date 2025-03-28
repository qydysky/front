package front

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/qydysky/front/filiter"
	plog "github.com/qydysky/part/log"
	reqf "github.com/qydysky/part/reqf"
	pweb "github.com/qydysky/part/web"
)

var logger = plog.New(plog.Config{
	Stdout: true,
	Prefix_string: map[string]struct{}{
		`T:`: plog.On,
		`I:`: plog.On,
		`W:`: plog.On,
		`E:`: plog.On,
	},
})

func Test_Uri2(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	web := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	web.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`//test/`: func(w http.ResponseWriter, r *http.Request) {
			io.Copy(w, r.Body)
		},
	})

	defer web.Shutdown()

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:    []string{"//test/"},
				PathAdd: true,
				Backs: []Back{
					{
						Name:   "1",
						To:     "://127.0.0.1:19001",
						Weight: 1,
					},
				},
			},
		},
	}

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	reqb := []byte("1234")
	resb := make([]byte, 5)

	pipe := reqf.NewRawReqRes()
	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url:     "http://127.0.0.1:19000//test/",
		RawPipe: pipe,
		Async:   true,
	}); e != nil {
		t.Fatal()
	}
	pipe.ReqWrite(reqb)
	pipe.ReqClose()
	n, _ := pipe.ResRead(resb)
	resb = resb[:n]
	if !bytes.Equal(resb, reqb) {
		t.Fatal(string(resb))
	}
}

func Test_Uri(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:    []string{"/"},
				PathAdd: true,
				Setting: Setting{
					Filiter: filiter.Filiter{
						ReqUri: filiter.Uri{
							AccessRule: "!{go}",
							Items: map[string]string{
								"go": "\\.go$",
							},
						},
					},
				},
				Backs: []Back{
					{
						Name:   "1",
						To:     "./",
						Weight: 1,
					},
				},
			},
		},
	}

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		if r.Response.StatusCode != http.StatusForbidden {
			t.Fail()
		}
	} else {
		t.Fail()
	}

	conf.Routes[0].Setting.Filiter.ReqUri.AccessRule = "{go}"

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		t.Fail()
	}
}

func Test_Back(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:    []string{"/"},
				PathAdd: true,
				Backs:   []Back{},
			},
		},
	}

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		if r.Response.StatusCode != http.StatusNotFound {
			t.Fail()
		}
	} else {
		t.Fail()
	}

	conf.Routes[0].Backs = append(conf.Routes[0].Backs,
		Back{
			Name:   "1",
			To:     "./",
			Weight: 1,
		},
	)
	conf.SwapSign(ctx, logger)

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		t.Fail()
	}

	conf.Routes[0].Backs = conf.Routes[0].Backs[:0]
	conf.SwapSign(ctx, logger)

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		if r.Response.StatusCode != http.StatusNotFound {
			t.Fail()
		}
	} else {
		t.Fail()
	}
}

func Test_Res(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	}).Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/`: func(w http.ResponseWriter, r *http.Request) {
			io.Copy(w, r.Body)
		},
	})

	conf := &Config{
		RetryBlocks: RetryBlocks{
			Num:  10,
			Size: "3B",
		},
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:    []string{"/"},
				PathAdd: true,
				Backs: []Back{
					{
						Name:   "1",
						To:     "://127.0.0.1:19001",
						Weight: 1,
					},
				},
			},
		},
	}

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	reqb := []byte("1234")
	resb := make([]byte, 5)

	pipe := reqf.NewRawReqRes()
	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url:     "http://127.0.0.1:19000/",
		RawPipe: pipe,
		Async:   true,
	}); e != nil {
		t.Fatal()
	}
	pipe.ReqWrite(reqb)
	pipe.ReqClose()
	n, _ := pipe.ResRead(resb)
	resb = resb[:n]
	if !bytes.Equal(resb, reqb) {
		t.Fatal(resb)
	}
}
