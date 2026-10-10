module example.com/parity

go 1.21

require (
	github.com/gin-gonic/gin v1.6.0
	golang.org/x/net v0.0.0-20200822124328-c89045814202 // indirect
	// github.com/commented/out v1.0.0
	gopkg.in/yaml.v2 v2.2.2
)

require github.com/pkg/errors v0.9.1

replace github.com/gin-gonic/gin => github.com/gin-gonic/gin v1.7.0
