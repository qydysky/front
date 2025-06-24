package filiter

import (
	"encoding/json"
	"unique"
	"unsafe"
)

func getId[T any](s T) uintptr {
	if d,e:=json.Marshal(s);e!=nil{
		return uintptr(unsafe.Pointer(&s))
	} else {
		u := unique.Make(string(d))
		return uintptr(unsafe.Pointer(&u))
	}
}