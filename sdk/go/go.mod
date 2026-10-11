// Module path matches the repository so `go get` works from the canonical URL.
// No dependencies: the protocol primitives are string and big-integer
// arithmetic, and a dependency on the authorization path of a project that
// enforces signed, digest-pinned manifests on everyone else's tools would be
// hard to defend.
module github.com/AGI-Gateway/XCP/sdk/go

go 1.22
