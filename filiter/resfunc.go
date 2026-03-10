package filiter

import (
	"net/http"

	boolS "github.com/qydysky/part/bools"
)

type ResFunc struct {
	AccessRule string                                                             `json:"-"`
	Items      map[string]func(req *http.Request, res *http.Response) (pass bool) `json:"-"`
}

func (t *ResFunc) Valid() bool {
	return t.AccessRule != "" && len(t.Items) != 0
}

func (t *ResFunc) Match(r *http.Request, res *http.Response) (bool, error) {
	if !t.Valid() {
		return true, nil
	}
	m := map[string]func() bool{}
	for k, v := range t.Items {
		m[k] = func() bool {
			return v(r, res)
		}
	}
	return boolS.New(t.AccessRule, m).Check()
}
