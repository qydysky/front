package filiter

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"unique"

	boolS "github.com/qydysky/part/bools"
)

type Uri struct {
	Id         unique.Handle[string] `json:"-"`
	AccessRule string                `json:"accessRule"`
	Items      map[string]string     `json:"items"`
}

func (t *Uri) UnmarshalJSON(b []byte) error {
	var s = struct {
		Id         unique.Handle[string] `json:"-"`
		AccessRule string                `json:"accessRule"`
		Items      map[string]string     `json:"items"`
	}{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s.Id = unique.Make(string(b))
	*t = s
	return nil
}

func (t *Uri) Valid() bool {
	return t.AccessRule != "" && len(t.Items) != 0
}

func (t *Uri) Match(r *http.Request) (bool, error) {
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
				return exp.MatchString(r.RequestURI)
			}
		}
	}
	return boolS.New(t.AccessRule, m).Check()
}
