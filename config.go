package main

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"sync"
)

type Config struct {
	lock      sync.RWMutex
	Addr      string  `json:"addr"`
	MatchRule string  `json:"matchRule"`
	Routes    []Route `json:"routes"`
}

type Route struct {
	Path string `json:"path"`
	Sign string `json:"-"`
	Back []Back `json:"back"`
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
	for _, back := range t.Back {
		tmpBack := Back{
			To:        back.To,
			Weight:    back.Weight,
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
	To        string   `json:"to"`
	Weight    int      `json:"weight"`
	ReqHeader []Header `json:"reqHeader"`
	ResHeader []Header `json:"resHeader"`
}

type Header struct {
	Action string `json:"action"`
	Key    string `json:"key"`
	Value  string `json:"value"`
}
