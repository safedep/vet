module example.com/app

go 1.22

require (
	github.com/acme/sdk v1.2.0
	github.com/acme/forked v1.0.0
)

replace github.com/acme/sdk => ../sdk

replace github.com/acme/forked => github.com/me/forked v1.0.1
