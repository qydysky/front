package dealer

type HeaderDealer struct {
	Key      string `json:"key"`
	MatchExp string `json:"matchExp"`
	Action   string `json:"action"`
	Value    string `json:"value"`
}
