package front

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/qydysky/front/filiter"
	plog "github.com/qydysky/part/log"
	reqf "github.com/qydysky/part/reqf"
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
