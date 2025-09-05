package dealer

type StatusDealer struct {
	MatchExp string `json:"matchExp,omitempty"`
	Value    int    `json:"value,omitempty"`
}

func (t *StatusDealer) Valid() bool {
	return t.Value != 0
}
