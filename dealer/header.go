package dealer

type HeaderDealer struct {
	Key      string `json:"key,omitempty"`
	MatchExp string `json:"matchExp,omitempty"`
	Action   string `json:"action,omitempty"`
	Value    string `json:"value,omitempty"`
}
