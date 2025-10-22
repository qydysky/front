package filiter

import (
	"log"
	"net/http"
	"regexp"

	boolS "github.com/qydysky/part/bools"
)

type Addr struct {
	AccessRule string            `json:"accessRule,omitempty"`
	Items      map[string]string `json:"items,omitempty"`
}

func (t *Addr) Valid() bool {
	return t.AccessRule != "" && len(t.Items) != 0
}

func (t *Addr) Match(r *http.Request) (bool, error) {
	if !t.Valid() {
		return true, nil
	}
	m := map[string]func() bool{}
	for k, v := range t.Items {
		m[k] = func() bool {
			if exp, e := regexp.Compile(v); e != nil {
				log.Default().Println(e)
				return false
			} else {
				return exp.MatchString(r.RemoteAddr)
			}
		}
	}
	return boolS.New(t.AccessRule, m).Check()
}
