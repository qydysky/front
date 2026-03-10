package filiter

import (
	"net/http"

	boolS "github.com/qydysky/part/bools"
)

type ReqFunc struct {
	AccessRule string                                       `json:"-"`
	Items      map[string]func(r *http.Request) (pass bool) `json:"-"`
}

func (t *ReqFunc) Valid() bool {
	return t.AccessRule != "" && len(t.Items) != 0
}

func (t *ReqFunc) Match(r *http.Request) (bool, error) {
	if !t.Valid() {
		return true, nil
	}
	m := map[string]func() bool{}
	for k, v := range t.Items {
		m[k] = func() bool {
			return v(r)
		}
	}
	return boolS.New(t.AccessRule, m).Check()
}
