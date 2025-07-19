module github.com/XXXXD-cation/OpenEDR/agent

go 1.23.0

toolchain go1.24.3

require (
	github.com/XXXXD-cation/OpenEDR/shared v0.0.0
	google.golang.org/grpc v1.73.0
	google.golang.org/protobuf v1.36.6
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250715232539-7130f93afb79 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/XXXXD-cation/OpenEDR/shared => ../shared
