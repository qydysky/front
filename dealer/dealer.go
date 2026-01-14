package dealer

type Dealer struct {
	ReqUri    []UriDealer    `json:"reqUri,omitempty"`
	ReqHeader []HeaderDealer `json:"reqHeader,omitempty"`
	// ReqFunc   ReqFunc        `json:"-"`
	ResHeader []HeaderDealer `json:"resHeader,omitempty"`
	ResBody   []Body         `json:"resBody,omitempty"`
	ResStatus StatusDealer   `json:"resStatus"`
	// ResFunc   ResFunc        `json:"-"`
}
