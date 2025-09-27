package front

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/qydysky/front/dealer"
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

func Test5(t *testing.T) {
	t.Log(filepath.Clean(".//dd.lof"))
}

func Benchmark1(b *testing.B) {
	// m := make(map[string]string)
	// m["123"] = "133"

	f := func(m map[string]string) bool {
		_, ok := m["123"]
		return ok
	}

	for b.Loop() {
		var m = make(map[string]string)
		m["123"] = "133"
		f(m)
	}
}

func Test_Uri6(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := []byte(`
	{
		"addr": "127.0.0.1:19000",
		"routes": [
			{
				"name": "1",
				"path": ["/test/"],
				"pathAdd": true,
				"filiters": [
					{
						"reqUri": {
							"accessRule": "{a}",
							"items": {
								"a": "2"
							}
						}
					}
				],
				"backs": [
					{
						"name": "1",
						"dealer": {
							"resStatus": {
								"value": 302
							}
						}
					}
				]
			},
			{
				"name": "2",
				"path": ["/test/"],
				"pathAdd": true,
				"backs": [
					{
						"name": "2",
						"dealer": {
							"resStatus": {
								"value": 301
							}
						}
					}
				]
			}
		]
	}
	`)

	conf := &Config{}
	if e := json.Unmarshal(j, conf); e != nil {
		t.Fatal(e)
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	r.Reqf(reqf.Rval{
		Ctx: ctx,
		Url: "http://127.0.0.1:19000/test/1",
	})

	r.Response(func(r *http.Response) error {
		if r.StatusCode != 301 {
			t.Fatal()
		}
		return nil
	})

	r.Reqf(reqf.Rval{
		Ctx: ctx,
		Url: "http://127.0.0.1:19000/test/2",
	})

	r.Response(func(r *http.Response) error {
		if r.StatusCode != 302 {
			t.Fatal()
		}
		return nil
	})
}

func Test_Uri5(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	j := []byte(`
	{
		"addr": "127.0.0.1:19000",
		"routes": [
			{
				"path": ["/test/"],
				"pathAdd": true,
				"backs": [
					{
						"name": "1",
						"dealer": {
							"resStatus": {
								"value": 301
							}
						}
					}
				]
			}
		]
	}
	`)

	conf := &Config{}
	if e := json.Unmarshal(j, conf); e != nil {
		t.Fatal(e)
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	r.Reqf(reqf.Rval{
		Ctx: ctx,
		Url: "http://127.0.0.1:19000/test/1",
	})

	r.Response(func(r *http.Response) error {
		if r.StatusCode != 301 {
			t.Fatal()
		}
		return nil
	})
}

func Test_Uri4(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	web := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	web.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/test/1`: func(w http.ResponseWriter, r *http.Request) {
			io.Copy(w, r.Body)
		},
	})

	defer web.Shutdown()

	time.Sleep(time.Second)

	j := []byte(`
	{
		"addr": "127.0.0.1:19000",
		"routes": [
			{
				"path": ["/test/"],
				"pathAdd": true,
				"backs": [
					{
						"name": "1",
						"to": "://127.0.0.1:19001",
						"filiters": [
							{
								"reqHost": {
									"accessRule": "{f}",
									"items": {
										"f": "127\\.0\\.0\\.1"
									}
								}
							}
						]
					}
				]
			}
		]
	}
	`)

	conf := &Config{}
	if e := json.Unmarshal(j, conf); e != nil {
		t.Fatal(e)
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	r.Reqf(reqf.Rval{
		Ctx:     ctx,
		Url:     "http://127.0.0.1:19000/test/1",
		PostStr: "123",
	})

	r.Respon(func(b []byte) error {
		if string(b) != "123" {
			t.Fatal(string(b))
		}
		return nil
	})
}

func Test_Uri3(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	web := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	web.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/test/1`: func(w http.ResponseWriter, r *http.Request) {
			io.Copy(w, r.Body)
		},
		`/test/2`: func(w http.ResponseWriter, r *http.Request) {
			io.Copy(w, r.Body)
		},
	})

	defer web.Shutdown()

	time.Sleep(time.Second)

	j := []byte(`
	{
		"addr": "127.0.0.1:19000",
		"routes": [
			{
				"path": ["/test/"],
				"pathAdd": true,
				"backs": [
					{
						"name": "1",
						"to": "://127.0.0.1:19001",
						"filiters": [
							{
								"reqUri": {
									"accessRule": "{f}",
									"items": {
										"f": "\/test\/2"
									}
								}
							},
							{
								"reqUri": {
									"accessRule": "{f}",
									"items": {
										"f": "\/test\/1"
									}
								}
							}
						]
					}
				]
			}
		]
	}
	`)

	conf := &Config{}
	if e := json.Unmarshal(j, conf); e != nil {
		t.Fatal(e)
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	r.Reqf(reqf.Rval{
		Ctx:     ctx,
		Url:     "http://127.0.0.1:19000/test/1",
		PostStr: "123",
	})

	r.Respon(func(b []byte) error {
		if string(b) != "123" {
			t.Fatal(string(b))
		}
		return nil
	})
	r.Reqf(reqf.Rval{
		Ctx:     ctx,
		Url:     "http://127.0.0.1:19000/test/2",
		PostStr: "123",
	})

	r.Respon(func(b []byte) error {
		if string(b) != "123" {
			t.Fatal(string(b))
		}
		return nil
	})
}

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
				Path: []string{"//test/"},
				Setting: Setting{
					PathAdd: true,
				},
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

	go conf.Run(ctx, logger)()

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

	customFiliter := &filiter.Filiter{
		ReqUri: filiter.Uri{
			AccessRule: "!{go}",
			Items: map[string]string{
				"go": "\\.go$",
			},
		},
	}

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path: []string{"/"},
				Setting: Setting{
					PathAdd:  true,
					Filiters: []*filiter.Filiter{customFiliter},
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
	go conf.Run(ctx, logger)()
	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		r.Response(func(r *http.Response) error {
			if r.StatusCode != http.StatusForbidden {
				t.Fail()
			}
			return nil
		})
	} else {
		t.Fail()
	}

	customFiliter.ReqUri.AccessRule = "{go}"

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
				Path: []string{"/"},
				Setting: Setting{
					PathAdd: true,
				},
				Backs: []Back{},
			},
		},
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		r.Response(func(r *http.Response) error {
			if r.StatusCode != http.StatusNotFound {
				t.Fatal(r.StatusCode)
			}
			return nil
		})
	} else {
		t.Fatal()
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
		t.Fatal()
	}

	conf.Routes[0].Backs = conf.Routes[0].Backs[:0]
	conf.SwapSign(ctx, logger)

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		r.Response(func(r *http.Response) error {
			if r.StatusCode != http.StatusNotFound {
				t.Fatal()
			}
			return nil
		})
	} else {
		t.Fatal()
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
		RetryBlocks: Blocks{
			Num:  10,
			Size: "3B",
		},
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path: []string{"/"},
				Setting: Setting{
					PathAdd: true,
				},
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

	go conf.Run(ctx, logger)()

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

func Test_Cookie(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c1 := "login_locale=zh_CN; Max-Age=31536000; Expires=Wed, 15 Apr 2026 02:29:42; Path=/"
	c2 := "login_locale=zh_CN; Max-Age=31536000; Expires=Wed, 15 Apr 2026 02:29:43; Path=/"
	c3 := "ts=11111111111"

	pweb.New(&http.Server{
		Addr: "127.0.0.1:19002",
	}).Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/`: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Set-Cookie", c1)
			w.Header().Add("Set-Cookie", c2)
			w.Header().Add("Set-Cookie", c3)
			io.Copy(w, r.Body)
		},
	})

	conf := &Config{
		RetryBlocks: Blocks{
			Num:  10,
			Size: "3B",
		},
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path: []string{"/"},
				Setting: Setting{
					PathAdd: true,
				},
				Backs: []Back{
					{
						Name:   "1",
						To:     "://127.0.0.1:19002",
						Weight: 1,
					},
				},
			},
		},
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url:     "http://127.0.0.1:19000/",
		PostStr: "123",
	}); e != nil {
		t.Fatal()
	}

	r.Response(func(r *http.Response) error {
		if v, ok := map[string][]string(r.Header)["Set-Cookie"]; !ok {
			t.Fatal(r.Header)
		} else if v[0] != c1 || v[1] != c2 || v[2] != c3 {
			t.Fatal()
		}
		return nil
	})
	// t.Log(r.Response.Header)
}

func Test_Retry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pweb.New(&http.Server{
		Addr: "127.0.0.1:19002",
	}).Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/`: func(w http.ResponseWriter, r *http.Request) {
			io.Copy(w, r.Body)
		},
	})

	conf := &Config{
		RetryBlocks: Blocks{
			Num:  10,
			Size: "3B",
		},
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path: []string{"/"},
				Setting: Setting{
					PathAdd: true,
				},
				RollRule: "order",
				Backs: []Back{
					{
						Name:   "1",
						To:     "://127.0.0.1:19001",
						Weight: 1,
					},
					{
						Name:   "1",
						To:     "://127.0.0.1:19002",
						Weight: 1,
					},
				},
			},
		},
	}

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/",
		// PostStr: "1",
	}); e != nil {
		t.Fatal()
	}
}

func Test_ResBody(t *testing.T) {
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
		RetryBlocks: Blocks{
			Num:  10,
			Size: "10B",
		},
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				Setting: Setting{
					PathAdd: true,
					Dealer: dealer.Dealer{
						ResBody: []dealer.Body{
							{
								Action:   "replace",
								MatchExp: "23",
								Value:    "ab",
							},
						},
					},
				},
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

	go conf.Run(ctx, logger)()

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url:     "http://127.0.0.1:19000/",
		PostStr: "12345",
	}); e != nil {
		t.Fatal()
	}

	r.Respon(func(b []byte) error {
		if string(b) != "1ab45" {
			t.Fatal(string(b))
		}
		return nil
	})
}
