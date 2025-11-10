package authz

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
	HostsCSV  = flag.String("hosts-csv", "", "rewrite nexthop hosts (format: from1=to1,from2=to2)")
	HostsURL  = flag.String("hosts-url", "", "URL to host mapping config (eg. https://github.com/myorg/beyond-config/main/raw/hosts.json)")
	HostsOnly = flag.Bool("hosts-only", false, "only allow requests to hosts in the host mapping")
	hostsMap  = map[string]string{}
)

// HostsSetup initializes host mappings from CSV configuration
func HostsSetup(cfg string) error {
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

// RefreshHosts loads host mappings from URL configuration
func RefreshHosts() error {
	if *HostsURL == "" {
		return nil
	}

	resp, err := httpACL.Get(*HostsURL)
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

// HostAllowed checks if a host is allowed based on hosts-only configuration
func HostAllowed(host string) bool {
	if !*HostsOnly {
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

// HostRewriteDetailed returns detailed host rewrite information
func HostRewriteDetailed(host string) *HostRewrite {
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

// RewriteHost returns the rewritten host (backward compatibility)
func RewriteHost(host string) string {
	return HostRewriteDetailed(host).Host
}

// GetHostsMap returns the current host mappings (for testing)
func GetHostsMap() map[string]string {
	return hostsMap
}

// SetHostsMap sets the host mappings (for testing)
func SetHostsMap(m map[string]string) {
	hostsMap = m
}
