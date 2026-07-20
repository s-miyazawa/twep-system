module github.com/s-miyazawa/twep-system

go 1.22

require (
	github.com/fxamacker/cbor/v2 v2.9.0
	github.com/veraison/go-cose v1.3.1-0.20251008083203-58542e2a46e9
)

require github.com/x448/float16 v0.8.4 // indirect

replace github.com/veraison/go-cose => github.com/kentakayama/go-cose v0.0.0-20260122035816-b936aa60847b
