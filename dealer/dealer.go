package dealer

type Dealer struct {
	ReqUri    []UriDealer    `json:"reqUri"`
	ReqHeader []HeaderDealer `json:"reqHeader"`
	ResHeader []HeaderDealer `json:"resHeader"`
}
