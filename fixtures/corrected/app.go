package sample
import "crypto/tls"
var ClientConfig = tls.Config{MinVersion: tls.VersionTLS12}
