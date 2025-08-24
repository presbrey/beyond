package beyond

import (
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	learnNexthops = flag.Bool("learn-nexthops", true, "set false to require explicit allowlisting")

	learnHTTPSPorts = flag.String("learn-https-ports", "443,4443,6443,8443,9443,9090", "try learning these backend HTTPS ports (csv)")
	learnHTTPPorts  = flag.String("learn-http-ports", "80,8080,6000,6060,7000,7070,8000,9000,9200,15672", "after HTTPS, try these HTTP ports (csv)")

	learnDialTimeout = flag.Duration("learn-dial-timeout", 8*time.Second, "skip port after this connection timeout")
)

func learn(host string) http.Handler {
	newBase := learnBase(host)
	if newBase != "" {
		u, err := url.Parse(newBase)
		if err == nil {
			return newSHRP(u)
		}
	}
	return nil
}

func learnBase(host string) string {
	if strings.Contains(host, ":") {
		if strings.HasPrefix(host, "https:") || strings.HasPrefix(host, "http:") {
			return host
		}
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: *learnDialTimeout}, "tcp", host, tlsConfig)
		if err == nil {
			c.Close()
			return "https://" + host
		}
		return "http://" + host
	}
	for _, httpsPort := range strings.Split(*learnHTTPSPorts, ",") {
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: *learnDialTimeout}, "tcp", host+":"+httpsPort, tlsConfig)
		if err == nil {
			c.Close()
			if httpsPort == "443" {
				return "https://" + host
			}
			return "https://" + host + ":" + httpsPort
		}
	}
	for _, httpPort := range strings.Split(*learnHTTPPorts, ",") {
		c, err := net.DialTimeout("tcp", host+":"+httpPort, *learnDialTimeout)
		if err == nil {
			c.Close()
			if httpPort == "80" {
				return "http://" + host
			}
			return "http://" + host + ":" + httpPort
		}
	}
	return ""
}
