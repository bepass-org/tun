module github.com/bepass-org/tun

go 1.21.1

replace gvisor.dev/gvisor => github.com/google/gvisor v0.0.0-20231222014442-b27cde5d928c

require (
	golang.org/x/crypto v0.17.0
	golang.org/x/sys v0.15.0
	gvisor.dev/gvisor v0.0.0-20231228213732-de71aae89aed
)

require (
	github.com/google/btree v1.1.2 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	golang.org/x/term v0.15.0 // indirect
	golang.org/x/time v0.3.0 // indirect
)
