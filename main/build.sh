#!/bin/sh
rm -rf front.*
CGO_ENABLED=0 go build  -buildmode=exe -o front.run .
CGO_ENABLED=0 GOOS=windows go build -buildmode=exe -o front.exe .
echo ok