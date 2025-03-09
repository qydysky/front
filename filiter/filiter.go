package filiter

type Filiter struct {
	ReqHeader Header `json:"reqHeader"`
	ReqUri    Uri    `json:"reqUri"`
	ResHeader Header `json:"resHeader"`
	ReqBody   Body   `json:"reqBody"`
}
