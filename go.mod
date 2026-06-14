module github.com/slsa-framework/slsa-attester

go 1.25.11

replace github.com/slsa-framework/slsa-core => ../slsa-core

require (
	github.com/carabiner-dev/command v0.3.1
	github.com/carabiner-dev/hasher v0.2.4
	github.com/in-toto/attestation v1.2.0
	github.com/slsa-framework/slsa-core v0.0.0
	github.com/spf13/cobra v1.10.2
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/carabiner-dev/signer v0.4.3 // indirect
	github.com/chainguard-dev/clog v1.8.0 // indirect
	github.com/cloudflare/circl v1.6.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/nozzle/throttler v0.0.0-20180817012639-2ea982251481 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/samber/slog-common v0.21.0 // indirect
	github.com/samber/slog-zap/v2 v2.6.4 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/text v0.36.0 // indirect
)
