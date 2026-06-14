module github.com/slsa-framework/slsa-attester

go 1.25.11

replace github.com/slsa-framework/slsa-core => ../slsa-core

require (
	github.com/in-toto/attestation v1.2.0
	google.golang.org/protobuf v1.36.11
)
