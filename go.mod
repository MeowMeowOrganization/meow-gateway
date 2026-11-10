module github.com/MeowMeowOrganization/meow-gateway

go 1.27.1

replace github.com/MeowMeowOrganization/meow-contracts => ../meow-contracts

require (
	connectrpc.com/connect v1.21.1
	github.com/MeowMeowOrganization/meow-contracts v0.0.0-00010101000000-000000000000
)

require google.golang.org/protobuf v1.36.12 // indirect
