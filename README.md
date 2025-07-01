# nXTLS: A Modern MIT-Licensed XTLS-Compatible TLS Library

nXTLS is a **modern, MIT-licensed reimplementation of XTLS**, designed for high-performance, privacy-oriented proxy systems. It is not affiliated with or derived from the original XTLS authors or codebase—every line is freshly written for clarity, extensibility, and compliance with permissive open-source licensing.

## Features

- **XTLS Origin & Direct Modes:** Full support for both XTLS operation modes:  
  - **Origin Mode:** Strict protocol monitoring, security checks, and fallback.  
  - **Direct Mode:** Minimal monitoring, maximum throughput, smart trailing alert suppression.
- **MIT License:** Free for any use, including commercial and closed-source projects.
- **Modern, Idiomatic Go:** Clean, maintainable code, fully compatible with the Go standard library's TLS API.
- **Detection Countermeasures:** Robust alert handling and detection avoidance, including defense against close_notify signature leaks.
- **Easy Integration:** Drop-in replacement for `crypto/tls.Conn` with XTLS-specific extensions.

## Getting Started

### 1. Installation

Clone or vendor this repository.  
(You may rename the import path as needed for your project.)

```sh
git clone https://github.com/nXTLS/Go
```

### 2. Basic Usage

nXTLS provides a superset of the standard Go TLS API.  
You create a connection as with `tls.Conn`, but can enable XTLS mode via a simple method.

```go
import (
    "https://github.com/nXTLS/Go"
    "net"
)

func main() {
    // Dial your raw TCP connection as usual.
    rawConn, err := net.Dial("tcp", "server.example.com:443")
    if err != nil {
        panic(err)
    }

    // Prepare your tls.Config as usual.
    config := &tls.Config{
        InsecureSkipVerify: true, // for testing only!
    }

    // Create the nXTLS connection:
    conn := tls.Client(rawConn, config)

    // Set XTLS mode (XTLSModeDirect or XTLSModeOrigin)
    conn.SetXTLSMode(tls.XTLSModeDirect)

    // Optional: enable detailed debug logs
    conn.EnableXTLSDebug(true)

    // Now use conn just like a standard tls.Conn
    _, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: ...\r\n\r\n"))
    // ...etc
}
```

#### Server Example

```go
listener, _ := net.Listen("tcp", ":443")
for {
    rawConn, _ := listener.Accept()
    config := &tls.Config{ /* ... */ }
    tlsConn := tls.Server(rawConn, config)
    tlsConn.SetXTLSMode(tls.XTLSModeOrigin) // or Direct
    go func() {
        defer tlsConn.Close()
        // Handle the connection
    }()
}
```

### 3. XTLS Modes Explained

- **XTLSModeOrigin:**  
  - Default. Provides strict protocol compliance, full monitoring of TLS records, detection and fallback on anomalies, and protection against active probing and MITM.
  - Use for maximum security and compatibility.

- **XTLSModeDirect:**  
  - Minimal protocol handling after handshake—records are passed through with only necessary trailing alert suppression.
  - Use for maximal throughput and lowest CPU usage in trusted environments.

You can switch modes at any point before data transfer.

### 4. Defensive Trailing Alert Handling

nXTLS ensures that in **Direct Mode**, all forms of trailing TLS alert records (including variable-length `close_notify`) are suppressed and never sent, mitigating detection risks and protocol fingerprinting.

### 5. Extending and Debugging

- Use `EnableXTLSDebug(true)` for verbose logging.
- The library exposes `XTLSConnState` for advanced state tracking and debugging.
- Integration with tunnels and transparent proxies is supported via `XTLSWriteDirect` and `XTLSReadDirect` helpers (see `xtls.go`).

### 6. Compatibility

- Fully compatible with Go's `crypto/tls` and existing XTLS-based clients/servers.
- Designed for use with VLESS, VMess, or any proxy needing XTLS/Direct/Origin support.

### 7. License

MIT License. See [LICENSE](LICENSE).

---

## Acknowledgements

- Inspired by the XTLS specification and community feedback.
- Not affiliated with or derived from the original XTLS authors or codebase.

---

## Advanced Usage

- See [xtls.go](xtls.go) for advanced helpers and manual record processing.
- See [conn.go](conn.go) for full protocol logic and state management.

---

## Questions or Issues?

Open an issue or pull request on GitHub.  
Contributions are welcome!
