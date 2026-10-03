package sample
import "crypto/tls"
var ClientConfig = tls.Config{InsecureSkipVerify: true}
