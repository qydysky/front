package dealer

import "github.com/qydysky/front/filiter"

type HeaderDealer struct {
	filiter.HeaderFiliter
	Action string `json:"action"`
	Value  string `json:"value"`
}
