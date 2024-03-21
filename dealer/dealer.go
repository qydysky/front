package dealer

type Dealer struct {
	ReqHeader []HeaderDealer `json:"reqHeader"`
	ResHeader []HeaderDealer `json:"resHeader"`
}
