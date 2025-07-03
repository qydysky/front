package dealer

type StatusDealer struct {
	MatchExp string `json:"matchExp"`
	Value    int    `json:"value"`
}

func (t *StatusDealer) Valid() bool {
	return t.Value != 0
}
