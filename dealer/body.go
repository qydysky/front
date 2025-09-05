package dealer

import (
	"regexp"
)

type Body struct {
	Action   string `json:"action,omitempty"`
	MatchExp string `json:"matchExp,omitempty"`
	Value    string `json:"value,omitempty"`
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
