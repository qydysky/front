package filiter

import (
	"net/http"
	"regexp"

	boolS "github.com/qydysky/part/bools"
)

type Header struct {
	AccessRule string                   `json:"accessRule"`
	Items      map[string]HeaderFiliter `json:"items"`
}

func (t *Header) Valid() bool {
	return t.AccessRule != "" && len(t.Items) != 0
}

func (t *Header) Match(h http.Header) (bool, error) {
	if !t.Valid() {
		return true, nil
	}
	m := map[string]func() bool{}
	for k, v := range t.Items {
		m[k] = func() bool { return v.Match(h) }
	}
	return boolS.New(t.AccessRule, m).Check()
}

type HeaderFiliter struct {
	Key      string `json:"key"`
	MatchExp string `json:"matchExp"`
}

func (t *HeaderFiliter) Match(h http.Header) bool {
	if t.MatchExp != "" {
		if exp, e := regexp.Compile(t.MatchExp); e != nil {
			return false
		} else {
			return exp.MatchString(h.Get(t.Key))
		}
	}
	return true
}
