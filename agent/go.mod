module github.com/XXXXD-cation/OpenEDR/agent

go 1.23.0

toolchain go1.24.3

require (
	github.com/XXXXD-cation/OpenEDR/shared v0.0.0
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250715232539-7130f93afb79 // indirect
)

replace github.com/XXXXD-cation/OpenEDR/shared => ../shared
