package beyond

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"strings"
)

// HostRewrite contains the rewritten host information
type HostRewrite struct {
	Host    string
	Scheme  string // http, https, or empty (preserve original)
	Port    string // port number or empty
	FullURL string // complete rewritten URL if available
}

var (
	hostsCSV  = flag.String("hosts-csv", "", "rewrite nexthop hosts (format: from1=to1,from2=to2)")
	hostsURL  = flag.String("hosts-url", "", "URL to host mapping config (eg. https://github.com/myorg/beyond-config/main/raw/hosts.json)")
	hostsOnly = flag.Bool("hosts-only", false, "only allow requests to hosts in the host mapping")
	hostsMap  = map[string]string{}
)

func hostsSetup(cfg string) error {
	if cfg == "" {
		return nil
	}
	for _, line := range strings.Split(cfg, ",") {
		elts := strings.Split(line, "=")
		if len(elts) < 2 {
			return fmt.Errorf("missing equals assignment in: %+v", line)
		}
		hostsMap[elts[0]] = elts[1]
	}
	return nil
}

func refreshHosts() error {
	if *hostsURL == "" {
		return nil
	}

	resp, err := httpACL.Get(*hostsURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var config map[string]string
	err = json.NewDecoder(resp.Body).Decode(&config)
	if err != nil {
		return err
	}

	// Merge URL config with command-line config
	for k, v := range config {
		hostsMap[k] = v
	}

	return nil
}

func hostAllowed(host string) bool {
	if !*hostsOnly {
		return true
	}

	// If hosts-only is enabled, check if host is in the mapping
	if len(hostsMap) == 0 {
		return false
	}

	for k := range hostsMap {
		if strings.HasSuffix(host, k) {
			return true
		}
	}
	return false
}

func hostRewriteDetailed(host string) *HostRewrite {
	result := &HostRewrite{Host: host}

	if len(hostsMap) == 0 {
		return result
	}

	for k, v := range hostsMap {
		if strings.HasSuffix(host, k) {
			// Check if replacement value is a full URL
			if strings.Contains(v, "://") {
				// Parse the URL to extract components
				if parsedURL, err := url.Parse(v); err == nil {
					result.Scheme = parsedURL.Scheme
					result.Port = parsedURL.Port()
					result.FullURL = v
					// For subdomain preservation, do string replacement on the hostname part
					result.Host = strings.Replace(host, k, parsedURL.Hostname(), -1)
				} else {
					// Fallback to simple string replacement if URL parsing fails
					result.Host = strings.Replace(host, k, v, -1)
				}
			} else {
				// Simple host replacement (backward compatibility)
				result.Host = strings.Replace(host, k, v, -1)
			}
			break
		}
	}
	return result
}

func hostRewrite(host string) string {
	// Backward compatibility - return just the host
	return hostRewriteDetailed(host).Host
}
