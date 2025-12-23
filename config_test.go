package front

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qydysky/front/dealer"
	"github.com/qydysky/front/filiter"
	pctx "github.com/qydysky/part/ctx"
	plog "github.com/qydysky/part/log/v2"
	reqf "github.com/qydysky/part/reqf"
	part "github.com/qydysky/part/sql"
	pweb "github.com/qydysky/part/web"
	_ "modernc.org/sqlite"
)

var logger = plog.New(&plog.Log{})

func Test5(t *testing.T) {
	t.Log(time.Now().Format("20060102150405.sqlite3"))
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

func Test1(t *testing.T) {
	db, err := sql.Open("sqlite", "./a")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer os.Remove("./a")
	defer db.Close()

	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	j := []byte(`
	{
		"addr": "127.0.0.1:19000",
		"routes": [
			{
				"name": "1",
				"path": ["/"],
				"backs": [
					{
						"name": "1"
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

	part.BeginTx(db, ctx).SimpleDo("create table log (date text, prefix text, base text, msgs text)").Run()

	logger := logger.Base(1).LDB(part.NewTxPool(db), part.PlaceHolderA, "insert into log (date,prefix,base,msgs) values ({Date},{Prefix},{Base},{Msgs})")

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	r.Reqf(reqf.Rval{
		Ctx: ctx,
		Url: "http://127.0.0.1:19000/",
	})

	r.Response(func(r *http.Response) error {
		if r.StatusCode != 200 {
			t.Fatal()
		}
		return nil
	})

	part.BeginTx(db, context.Background()).SimpleDo("select count(*) c from log").AfterQF(func(rows *sql.Rows) error {
		c, _ := part.DealRowMap(rows).Raw["c"].(int64)
		t.Log(c)
		if c != 3 {
			t.Fatal()
		}
		return nil
	}).Run()
}

func Test_Uri6(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

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

	go conf.Run(ctx, logger)

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
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

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

	go conf.Run(ctx, logger)

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

func Test_Uri7(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	var once atomic.Bool
	web := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	web.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/test/`: func(w http.ResponseWriter, r *http.Request) {
			if once.CompareAndSwap(false, true) {
				time.Sleep(time.Second * 10)
			}
			io.Copy(w, r.Body)
		},
	})

	defer web.Shutdown()

	j := []byte(`
	{
		"addr": "127.0.0.1:19002",
		"routes": [
			{
				"path": ["/test/"],
				"pathAdd": true,
				"name": "1",
				"backs": [
					{
						"name": "1",
						"to": "://127.0.0.1:19001"
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

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	var wg sync.WaitGroup
	wg.Add(100)
	for range 100 {
		go func() {
			if e := reqf.New().Reqf(reqf.Rval{
				Ctx:     ctx,
				Url:     "http://127.0.0.1:19002/test/",
				PostStr: "unitofmeas=EA&partdescr=PACKING&qtyreceived=21&originalSerialNo=0081027865&syncId=20251113112344&serialno=M00005&expiryDate=2031-03-31&soDtlId=9892095&pOno=225026385&receiptUser=014437 张邦宇&primaryLocation=NRC06&mroRevId=1988809975137153024&createdUser=014437 张邦宇&waybillno=176-19009196&commentNode=mroBackRun&partno=MS28775-130&owner=GAMECO&orderNo=&certificateType2=BN&alternatePartno=MS28775-130&certificateType1=COC&certificateNum2=0081027865&certificateNum1=1&warehouse=03&apeAddr=http://10.240.3.52:8080/apeme/&conditionCode=&widId=1988809975137153024&linenoAlt=001&qty=21&isExpiryDate=Y&location=NRC06&labelqty=1&isLot=0&operation=PO收货&",
			}); e != nil {
				t.Fatal(e)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}

func Test_Uri4(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	web := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	web.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/test/1/1`: func(w http.ResponseWriter, r *http.Request) {
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

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	r.Reqf(reqf.Rval{
		Ctx:     ctx,
		Url:     "http://127.0.0.1:19000/test/1/1",
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
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

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

	go conf.Run(ctx, logger)

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
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

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

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	pipe := reqf.NewRawReqRes()
	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url:     "http://127.0.0.1:19000//test/",
		RawPipe: pipe,
		Async:   true,
	}); e != nil {
		t.Fatal()
	}

	reqb := []byte("1234")
	resb := make([]byte, 5)
	pipe.ReqWrite(reqb)
	pipe.ReqClose()
	n, _ := pipe.ResRead(resb)
	resb = resb[:n]
	if !bytes.Equal(resb, reqb) {
		t.Fatal(string(resb))
	}
}

func Test_Uri(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

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
	go conf.Run(ctx, logger)
	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		r.Response(func(r *http.Response) error {
			if r.StatusCode != http.StatusForbidden {
				t.Fatal()
			}
			return nil
		})
	} else {
		t.Fatal()
	}

	customFiliter.ReqUri.AccessRule = "{go}"

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/config_test.go",
	}); e != nil {
		t.Fatal()
	}
}

func Test_Back(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

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

	go conf.Run(ctx, logger)

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
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
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

func Test_Cookie(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	c1 := "login_locale=zh_CN; Max-Age=31536000; Expires=Wed, 15 Apr 2026 02:29:42; Path=/"
	c2 := "login_locale=zh_CN; Max-Age=31536000; Expires=Wed, 15 Apr 2026 02:29:43; Path=/"
	c3 := "ts=11111111111"

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19002",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
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

	go conf.Run(ctx, logger)

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
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19002",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
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

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/",
		// PostStr: "1",
	}); e != nil {
		t.Fatal()
	}
}

func Test_Retry2(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19002",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/1/`: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{'2'})
		},
	})

	conf := &Config{
		RetryBlocks: Blocks{
			Num:  10,
			Size: "3B",
		},
		Addr: "127.0.0.1:19003",
		Routes: []Route{
			{
				Name:     "1",
				Path:     []string{"/1/"},
				AlwaysUp: true,
				Setting: Setting{
					PathAdd: true,
					Filiters: []*filiter.Filiter{
						{
							ReqHeader: filiter.Header{
								AccessRule: "{access}",
								Items: map[string]filiter.HeaderFiliter{
									"access": {
										Key:      "X-P-BACK",
										MatchExp: "19001",
									},
								},
							},
						},
					},
				},
				RollRule: "loop",
				Backs: []Back{
					{
						Name:   "1",
						To:     "://127.0.0.1:19001",
						Weight: 1,
					},
				},
			},
			{
				Name:     "2",
				Path:     []string{"/1/"},
				AlwaysUp: true,
				Setting: Setting{
					PathAdd: true,
				},
				RollRule: "loop",
				Backs: []Back{
					{
						Name:   "2",
						To:     "://127.0.0.1:19002",
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
		Url: "http://127.0.0.1:19003/1/",
	}); e != nil {
		t.Fatal(e)
	} else {
		_ = r.Respon(func(b []byte) error {
			if b[0] != '2' {
				t.Fatal()
			}
			return nil
		})
	}
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19003/1/",
		Header: map[string]string{
			"X-P-BACK": "19001",
		},
	}); e != nil {
		t.Fatal()
	} else {
		_ = r.Respon(func(b []byte) error {
			if b[0] != '2' {
				t.Fatal()
			}
			return nil
		})
	}

	// first up
	w2 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	w2.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/1/`: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{'1'})
		},
	})

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19003/1/",
		Header: map[string]string{
			"X-P-BACK": "19001",
		},
	}); e != nil {
		t.Fatal()
	} else {
		_ = r.Respon(func(b []byte) error {
			if b[0] != '1' {
				t.Fatal()
			}
			return nil
		})
	}

	w2.Shutdown()

	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19003/1/",
		Header: map[string]string{
			"X-P-BACK": "19001",
		},
	}); e != nil {
		t.Fatal()
	} else {
		_ = r.Respon(func(b []byte) error {
			if b[0] != '2' {
				t.Fatal()
			}
			return nil
		})
	}
}

func Test_ResBody(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
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

	go conf.Run(ctx, logger)

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

func Test_AlwaysUp(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/`: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{'1'})
		},
	})

	time.Sleep(time.Second)

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				AlwaysUp: true,
				Setting: Setting{
					PathAdd:   true,
					ErrBanSec: 2,
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

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)
	conf.Routes[0].Backs[0].Disable()

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/",
	}); e != nil {
		t.Fatal(e)
	} else {
		r.Respon(func(b []byte) error {
			if b[0] != '1' {
				t.Fatal()
			}
			return nil
		})
	}
}

func Test_Filiter(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				Setting: Setting{
					PathAdd: true,
					Filiters: []*filiter.Filiter{
						{
							ReqHeader: filiter.Header{
								AccessRule: "{access}",
								Items: map[string]filiter.HeaderFiliter{
									"access": {
										Key:      "X-P-A",
										MatchExp: "1",
									},
								},
							},
						},
					},
				},
				Backs: []Back{
					{
						Name:   "1",
						Weight: 1,
						Setting: Setting{
							Filiters: []*filiter.Filiter{
								{
									ReqHeader: filiter.Header{
										AccessRule: "{access}",
										Items: map[string]filiter.HeaderFiliter{
											"access": {
												Key:      "X-P-B",
												MatchExp: "1",
											},
										},
									},
								},
							},
							Dealer: dealer.Dealer{
								ResStatus: dealer.StatusDealer{
									Value: 201,
								},
							},
						},
					},
				},
			},
			{
				Path:     []string{"/"},
				RollRule: "order",
				Setting: Setting{
					PathAdd: true,
				},
				Backs: []Back{
					{
						Name:   "2",
						Weight: 1,
						Setting: Setting{
							Dealer: dealer.Dealer{
								ResStatus: dealer.StatusDealer{
									Value: 202,
								},
							},
						},
					},
				},
			},
		},
	}

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/",
		Header: map[string]string{
			"X-P-A": "1",
			"X-P-B": "1",
		},
	}); e != nil {
		t.Fatal(e)
	} else if r.ResStatusCode() != 201 {
		t.Fatal()
	}
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/",
		Header: map[string]string{
			"X-P-A": "1",
		},
	}); e != nil {
		t.Fatal(e)
	} else if r.ResStatusCode() != 202 {
		t.Fatal()
	}
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/",
	}); e != nil {
		t.Fatal(e)
	} else if r.ResStatusCode() != 202 {
		t.Fatal()
	}
}

func Test_TO(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/1`: func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(2 * time.Second)
		},
		`/2`: func(w http.ResponseWriter, r *http.Request) {
			pweb.WithFlush(w).Write([]byte{'1'})
			time.Sleep(2 * time.Second)
		},
	})

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				AlwaysUp: true,
				Setting: Setting{
					CtxToSec: 1,
					PathAdd:  true,
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

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/1",
	}); e != nil {
		if r.ResStatusCode() != http.StatusGatewayTimeout {
			t.Fatal(e)
		}
	}
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/2",
	}); e != nil {
		if r.ResStatusCode() != http.StatusGatewayTimeout {
			t.Fatal(e)
		}
	}
}

func Test_Shutdown(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				AlwaysUp: true,
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

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/1`: func(w http.ResponseWriter, r *http.Request) {
			go done()
			time.Sleep(time.Second)
			w.Write([]byte{'1'})
		},
	})

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/1",
	}); e != nil {
		t.Fatal(e)
	} else if e := r.Respon(func(b []byte) error {
		if b[0] != '1' {
			return errors.New("1")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}

func Test_ReFlash(t *testing.T) {
	ctx, done := pctx.WithWait(t.Context(), 0, time.Minute)
	defer done()

	conf := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				AlwaysUp: true,
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
	conf1 := &Config{
		Addr: "127.0.0.1:19000",
		Routes: []Route{
			{
				Path:     []string{"/"},
				RollRule: "order",
				AlwaysUp: true,
				Setting: Setting{
					PathAdd: true,
				},
				Backs: []Back{
					{
						Name:   "2",
						To:     "://127.0.0.1:19001",
						Weight: 1,
					},
				},
			},
		},
	}

	w1 := pweb.New(&http.Server{
		Addr: "127.0.0.1:19001",
	})
	defer w1.Shutdown()
	w1.Handle(map[string]func(http.ResponseWriter, *http.Request){
		`/1`: func(w http.ResponseWriter, r *http.Request) {
			go done()
			go conf1.Run(t.Context(), logger)
			time.Sleep(time.Second)

			r3 := reqf.New()
			if e := r3.Reqf(reqf.Rval{
				Url: "http://127.0.0.1:19000/2",
			}); e != nil {
				t.Fatal(e)
			} else if e := r3.Respon(func(b []byte) error {
				if b[0] != '2' {
					return errors.New("2")
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}

			w.Write([]byte{'1'})
		},
		`/2`: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte{'2'})
		},
	})

	go conf.Run(ctx, logger)

	time.Sleep(time.Second)

	r := reqf.New()
	if e := r.Reqf(reqf.Rval{
		Url: "http://127.0.0.1:19000/1",
	}); e != nil {
		t.Fatal(e)
	} else if e := r.Respon(func(b []byte) error {
		if b[0] != '1' {
			return errors.New("1")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
