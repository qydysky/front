package front

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Config struct {
	lock sync.RWMutex
	Addr string `json:"addr"`
	TLS  struct {
		Pub string `json:"pub"`
		Key string `json:"key"`
	} `json:"tls"`
	MatchRule string  `json:"matchRule"`
	Routes    []Route `json:"routes"`
}

type Route struct {
	Path        string `json:"path"`
	Sign        string `json:"-"`
	ErrRedirect bool   `json:"errRedirect"`
	Back        []Back `json:"back"`
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
		tmpBack := Back{
			Name:      back.Name,
			To:        back.To,
			Weight:    back.Weight,
			ErrBanSec: back.ErrBanSec,
			PathAdd:   back.PathAdd,
			ReqHeader: append([]Header{}, back.ReqHeader...),
			ResHeader: append([]Header{}, back.ResHeader...),
		}
		for i := 1; i <= back.Weight; i++ {
			backLink = append(backLink, &tmpBack)
		}
	}
	return backLink
}

type Back struct {
	lock      sync.RWMutex
	upT       time.Time
	Name      string   `json:"name"`
	To        string   `json:"to"`
	Weight    int      `json:"weight"`
	ErrBanSec int      `json:"errBanSec"`
	PathAdd   bool     `json:"pathAdd"`
	ReqHeader []Header `json:"reqHeader"`
	ResHeader []Header `json:"resHeader"`
}

func (t *Back) IsLive() bool {
	t.lock.RLock()
	defer t.lock.RUnlock()
	return t.upT.Before(time.Now())
}

func (t *Back) Disable() {
	t.lock.Lock()
	defer t.lock.Unlock()
	t.upT = time.Now().Add(time.Second * time.Duration(t.ErrBanSec))
}

type Header struct {
	Action string `json:"action"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}
