// The fasthttp adapter is a separate module so that net/http users do not
// inherit fasthttp and its dependencies. Tagged as
// middleware/fasthttp/vX.Y.Z, independently of the core.
module github.com/plainidio/plainid-go-authz/middleware/fasthttp

go 1.22

require (
	github.com/plainidio/plainid-go-authz v1.0.0
	github.com/valyala/fasthttp v1.58.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
)
