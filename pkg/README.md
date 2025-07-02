# XTLS-API (nXTLS Compatibility Glue)

This package provides an **XTLS-compatible API layer** for projects migrating from the classic [XTLS](https://github.com/XTLS/Go) protocol to the modern [nXTLS](https://github.com/nXTLS/Go) implementation.  
It allows you to use nXTLS as a **drop-in replacement** for XTLS in most Go projects, with minimal or no code changes.

---

## Features

- **Drop-in API:** Compatible with standard XTLS usage (`Dial`, `Listen`, `NewConn`, flow control, etc.)
- **Full `net.Conn` compatibility:** All methods (`Read`, `Write`, `Close`, deadlines, etc.) are preserved.
- **TLS/XTLS Flow Control:** Easily switch between `origin` and `direct` modes using `SetFlow`.
- **nXTLS Internals Access:** Expose the underlying nXTLS connection for advanced use.
- **Production ready:** Clean, idiomatic Go code, no legacy dependencies, no copyright risk.

---

## Usage

### Import

```go
import "github.com/nXTLS/Go/pkg/xtls"
```

### Client Example

```go
cfg := &xtls.Config{
    // ... your TLS config ...
}
conn, err := xtls.Dial("tcp", "example.com:443", cfg)
if err != nil {
    panic(err)
}
defer conn.Close()

conn.SetFlow(xtls.RPRXDirect) // or xtls.RPRXOrigin

_, err = conn.Write([]byte("hello"))
// ... use conn as net.Conn ...
```

### Server Example

```go
cfg := &xtls.Config{
    // ... your TLS config ...
}
ln, err := xtls.Listen("tcp", ":443", cfg)
if err != nil {
    panic(err)
}
for {
    c, err := ln.Accept()
    if err != nil {
        continue
    }
    go func(conn net.Conn) {
        defer conn.Close()
        // handle connection
    }(c)
}
```

---

## API Quick Reference

- `func Dial(network, addr string, config *Config) (*Conn, error)`
- `func Listen(network, addr string, config *Config) (net.Listener, error)`
- `func NewConn(net.Conn, *Config) *Conn`
- `func (c *Conn) SetFlow(flow string)` (`xtls.RPRXOrigin` or `xtls.RPRXDirect`)
- `func (c *Conn) EnableDebug(enable bool)`
- `func (c *Conn) ConnectionState() tls.ConnectionState`
- `func (c *Conn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)`
- `func (c *Conn) Underlying() *nxtls.Conn`
- All `net.Conn` methods supported.

---

## Migration Notes

- Replace your `import "github.com/xtls/go"` or `"github.com/XTLS/Go/pkg/xtls"` with `import "github.com/nXTLS/Go/pkg/xtls"`.
- All major XTLS patterns should work out-of-the-box.
- Use `SetFlow` to select between `"xtls-rprx-origin"` (default) and `"xtls-rprx-direct"` modes.
- Advanced TLS features (ALPN, session resumption, etc.) are transparently supported if enabled in nXTLS.

---

## License

MIT License.  
Copyright (c) nXTLS contributors.

---
