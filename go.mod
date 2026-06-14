module github.com/slsa-framework/slsa-attester

go 1.25.11

replace github.com/slsa-framework/slsa-core => ../slsa-core

require (
	github.com/carabiner-dev/hasher v0.2.4
	github.com/in-toto/attestation v1.2.0
	github.com/slsa-framework/slsa-core v0.0.0
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/nozzle/throttler v0.0.0-20180817012639-2ea982251481 // indirect
	golang.org/x/crypto v0.50.0 // indirect
	golang.org/x/sys v0.43.0 // indirect
)
