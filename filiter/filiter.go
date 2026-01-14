package filiter

import (
	"encoding/json"
	"unique"
)

type Filiter struct {
	id        unique.Handle[string] `json:"-"`
	ReqBody   Body                  `json:"reqBody"`
	ReqAddr   Addr                  `json:"reqAddr"`
	ReqHeader Header                `json:"reqHeader"`
	ReqHost   Host                  `json:"reqHost"`
	ReqUri    Uri                   `json:"reqUri"`
	ResHeader Header                `json:"resHeader"`
	ReqFunc   ReqFunc               `json:"reqFunc"`
	ResFunc   ResFunc               `json:"resFunc"`
}

func (t *Filiter) Id() *unique.Handle[string] {
	return &t.id
}

func (t *Filiter) UnmarshalJSON(b []byte) error {
	var s = struct {
		id        unique.Handle[string] `json:"-"`
		ReqBody   Body                  `json:"reqBody"`
		ReqAddr   Addr                  `json:"reqAddr"`
		ReqHeader Header                `json:"reqHeader"`
		ReqHost   Host                  `json:"reqHost"`
		ReqUri    Uri                   `json:"reqUri"`
		ResHeader Header                `json:"resHeader"`
		ReqFunc   ReqFunc               `json:"reqFunc"`
		ResFunc   ResFunc               `json:"resFunc"`
	}{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s.id = unique.Make(string(b))
	*t = s
	return nil
}
