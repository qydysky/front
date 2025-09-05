package dealer

type Dealer struct {
	ReqUri    []UriDealer    `json:"reqUri,omitempty"`
	ReqHeader []HeaderDealer `json:"reqHeader,omitempty"`
	ResHeader []HeaderDealer `json:"resHeader,omitempty"`
	ResBody   []Body         `json:"resBody,omitempty"`
	ResStatus StatusDealer   `json:"resStatus,omitempty"`
}
