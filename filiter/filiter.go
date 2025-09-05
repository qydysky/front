package filiter

import (
	"encoding/json"
	"unique"
)

type Filiter struct {
	id        unique.Handle[string] `json:"-"`
	ReqHeader Header                `json:"reqHeader,omitempty"`
	ReqHost   Host                  `json:"reqHost,omitempty"`
	ReqUri    Uri                   `json:"reqUri,omitempty"`
	ResHeader Header                `json:"resHeader,omitempty"`
	ReqBody   Body                  `json:"reqBody,omitempty"`
}

func (t *Filiter) Id() *unique.Handle[string] {
	return &t.id
}

func (t *Filiter) UnmarshalJSON(b []byte) error {
	var s = struct {
		id        unique.Handle[string] `json:"-"`
		ReqHeader Header                `json:"reqHeader,omitempty"`
		ReqHost   Host                  `json:"reqHost,omitempty"`
		ReqUri    Uri                   `json:"reqUri,omitempty"`
		ResHeader Header                `json:"resHeader,omitempty"`
		ReqBody   Body                  `json:"reqBody,omitempty"`
	}{}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	s.id = unique.Make(string(b))
	*t = s
	return nil
}
