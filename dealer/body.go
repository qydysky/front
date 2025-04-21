package dealer

import (
	"regexp"
)

type Body struct {
	Action   string `json:"action"`
	MatchExp string `json:"matchExp"`
	Value    string `json:"value"`
}

func (t *Body) Valid() bool {
	return t.MatchExp != ""
}

func (t *Body) GetReplaceDealer() (f func(data []byte) (dealed []byte, stop bool)) {
	f = func(data []byte) (dealed []byte, stop bool) {
		dealed = data
		return
	}
	if !t.Valid() {
		return
	}
	if exp, e := regexp.Compile(t.MatchExp); e == nil {
		return func(data []byte) (dealed []byte, stop bool) {
			dealed = exp.ReplaceAll(data, []byte(t.Value))
			stop = false
			return
		}
	} else {
		return
	}
}
