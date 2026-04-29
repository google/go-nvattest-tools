module github.com/google/go-nvattest-tools

go 1.25.0

require (
	github.com/NVIDIA/go-nvml v0.13.0-1
	github.com/beevik/etree v1.6.0
	github.com/google/go-cmp v0.7.0
	github.com/lestrrat-go/libxml2 v0.0.0-20260304224138-bb3877930cf7
	github.com/pkg/errors v0.9.1
	github.com/russellhaering/goxmldsig v1.6.0
	github.com/stretchr/testify v1.11.1
	go.uber.org/multierr v1.11.0
	golang.org/x/crypto v0.50.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/russellhaering/goxmldsig => github.com/atulpatildbz/goxmldsig v0.0.0-20260325075722-e806be5e3c3a
