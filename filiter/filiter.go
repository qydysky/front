package filiter

import (
	"encoding/json"
	"unique"
)

type Filiter struct {
	id        unique.Handle[string] `json:"-"`
	ReqHeader Header                `json:"reqHeader"`
	ReqUri    Uri                   `json:"reqUri"`
	ResHeader Header                `json:"resHeader"`
	ReqBody   Body                  `json:"reqBody"`
}

func (t *Filiter) Id() *unique.Handle[string] {
	return &t.id
}

func (t *Filiter) UnmarshalJSON(b []byte) error {
	var s = struct {
		id        unique.Handle[string] `json:"-"`
		ReqHeader Header                `json:"reqHeader"`
		ReqUri    Uri                   `json:"reqUri"`
		ResHeader Header                `json:"resHeader"`
		ReqBody   Body                  `json:"reqBody"`
	}{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s.id = unique.Make(string(b))
	*t = s
	return nil
}
