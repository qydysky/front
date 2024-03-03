package front

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	pslice "github.com/qydysky/part/slice"
)

type Config struct {
	lock sync.RWMutex
	Sign []*Route `json:"-"`
	Addr string   `json:"addr"`
	TLS  struct {
		Config *tls.Config `json:"-"`
		Pub    string      `json:"pub"`
		Key    string      `json:"key"`
	} `json:"tls"`
	MatchRule  string               `json:"matchRule"`
	CopyBlocks int                  `json:"copyBlocks"`
	BlocksI    pslice.BlocksI[byte] `json:"-"`
	Routes     []Route              `json:"routes"`
}

func (t *Config) SwapSign() []*Route {
	var delRoute []*Route
	for i := 0; i < len(t.Sign); i++ {
		var exist bool
		for k := 0; k < len(t.Routes); k++ {
			if t.Sign[i].Path == t.Routes[k].Path {
				exist = true
				break
			}
		}
		if !exist {
			delRoute = append(delRoute, t.Sign[i])
		}
	}

	t.Sign = t.Sign[:0]

	for i := 0; i < len(t.Routes); i++ {
		t.Sign = append(t.Sign, &t.Routes[i])
	}

	return delRoute
}

type Route struct {
	Path     string `json:"path"`
	Sign     string `json:"-"`
	Splicing int    `json:"splicing"`
	PathAdd  bool   `json:"pathAdd"`
	Back     []Back `json:"back"`
}

func (t *Route) SwapSign() bool {
	data, _ := json.Marshal(t)
	w := md5.New()
	w.Write(data)
	sign := fmt.Sprintf("%x", w.Sum(nil))
	if t.Sign != sign {
		t.Sign = sign
		return true
	}
	return false
}

func (t *Route) GenBack() []*Back {
	var backLink []*Back
	for i := 0; i < len(t.Back); i++ {
		back := &t.Back[i]
		back.SwapSign()
		if back.Weight == 0 {
			continue
		}
		tmpBack := Back{
			Name:        back.Name,
			Splicing:    t.Splicing,
			Sign:        back.Sign,
			To:          back.To,
			Weight:      back.Weight,
			ErrBanSec:   back.ErrBanSec,
			PathAdd:     t.PathAdd,
			MatchHeader: append([]Header{}, back.MatchHeader...),
			ReqHeader:   append([]Header{}, back.ReqHeader...),
			ResHeader:   append([]Header{}, back.ResHeader...),
		}
		for i := 1; i <= back.Weight; i++ {
			backLink = append(backLink, &tmpBack)
		}
	}
	return backLink
}

func FiliterBackByRequest(backs []*Back, r *http.Request) []*Back {
	var backLink []*Back
	for i := 0; i < len(backs); i++ {
		matchs := len(backs[i].MatchHeader) - 1
		for ; matchs >= 0 &&
			r.Header.Get(backs[i].MatchHeader[matchs].Key) == backs[i].MatchHeader[matchs].Value; matchs -= 1 {
		}
		if matchs == -1 && backs[i].IsLive() {
			backLink = append(backLink, backs[i])
		}
	}
	return backLink
}

type Back struct {
	lock        sync.RWMutex
	Sign        string `json:"-"`
	Splicing    int    `json:"-"`
	PathAdd     bool   `json:"-"`
	upT         time.Time
	Name        string   `json:"name"`
	To          string   `json:"to"`
	Weight      int      `json:"weight"`
	ErrBanSec   int      `json:"errBanSec"`
	MatchHeader []Header `json:"matchHeader"`
	ReqHeader   []Header `json:"reqHeader"`
	ResHeader   []Header `json:"resHeader"`
}

func (t *Back) SwapSign() bool {
	data, _ := json.Marshal(t)
	w := md5.New()
	w.Write(data)
	sign := fmt.Sprintf("%x", w.Sum(nil))
	if t.Sign != sign {
		t.Sign = sign
		return true
	}
	return false
}

func (t *Back) IsLive() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.upT.Before(time.Now())
}

func (t *Back) Disable() {
	if t.ErrBanSec == 0 {
		t.ErrBanSec = 1
	}
	t.lock.Lock()
	defer t.lock.Unlock()
	t.upT = time.Now().Add(time.Second * time.Duration(t.ErrBanSec))
}

type Header struct {
	Action string `json:"action"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}
