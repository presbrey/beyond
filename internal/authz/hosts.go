package authz

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
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

func init() {
	flag.StringVar(HostsCSV, "host-masq", "", "legacy alias for -hosts-csv")
}

// HostsSetup initializes host mappings from CSV configuration
func HostsSetup(cfg string) error {
	if cfg == "" {
		return nil
	}
	for _, line := range strings.Split(cfg, ",") {
		elts := strings.SplitN(line, "=", 2)
		if len(elts) < 2 {
			return fmt.Errorf("missing equals assignment in: %+v", line)
		}
		key, value := strings.TrimSpace(elts[0]), strings.TrimSpace(elts[1])
		if err := validateMapping(key, value); err != nil {
			return err
		}
		hostsMap[key] = value
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

	for k, v := range config {
		if err := validateMapping(k, v); err != nil {
			return err
		}
	}

	// Merge URL config with command-line config
	for k, v := range config {
		hostsMap[k] = v
	}

	return nil
}

// splitAuthority normalizes a hostname while retaining its optional port.
func splitAuthority(authority string) (string, string) {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		host, port = strings.Trim(authority, "[]"), ""
	}
	return strings.ToLower(strings.TrimSuffix(host, ".")), port
}

func joinAuthority(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}

func validateMapping(key, value string) error {
	if key == "" || value == "" || strings.ContainsAny(key, "/ \t") {
		return fmt.Errorf("invalid host mapping %q=%q", key, value)
	}
	target := value
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return fmt.Errorf("invalid host mapping target %q", value)
	}
	return nil
}

// matchingHost chooses the most specific mapping at a DNS label boundary.
func matchingHost(authority string) (string, string, bool) {
	host, port := splitAuthority(authority)
	var bestKey, bestValue string
	for key, value := range hostsMap {
		keyHost, keyPort := splitAuthority(key)
		if keyHost == "" || (keyPort != "" && keyPort != port) {
			continue
		}
		matches := host == keyHost
		if net.ParseIP(keyHost) == nil {
			matches = matches || strings.HasSuffix(host, "."+keyHost)
		}
		bestHost, bestPort := splitAuthority(bestKey)
		moreSpecific := len(keyHost) > len(bestHost) ||
			(len(keyHost) == len(bestHost) && keyPort != "" && bestPort == "")
		tied := len(keyHost) == len(bestHost) && (keyPort == "") == (bestPort == "")
		if matches && (moreSpecific || (tied && key < bestKey)) {
			bestKey, bestValue = key, value
		}
	}
	return bestKey, bestValue, bestKey != ""
}

// HostAllowed checks if a host is allowed based on hosts-only configuration.
func HostAllowed(host string) bool {
	if !*HostsOnly {
		return true
	}
	_, _, matched := matchingHost(host)
	return matched
}

// HostRewriteDetailed returns a consistent hostname and URL for the backend.
func HostRewriteDetailed(authority string) *HostRewrite {
	result := &HostRewrite{Host: authority}
	key, value, matched := matchingHost(authority)
	if !matched {
		return result
	}
	host, incomingPort := splitAuthority(authority)
	keyHost, _ := splitAuthority(key)
	prefix := strings.TrimSuffix(host, keyHost)
	if strings.Contains(value, "://") {
		u, err := url.Parse(value)
		if err != nil || u.Hostname() == "" {
			return result
		}
		result.Host = prefix + u.Hostname()
		result.Scheme, result.Port = u.Scheme, u.Port()
		u.Host = joinAuthority(result.Host, result.Port)
		result.FullURL = u.String()
	} else {
		targetHost, targetPort := splitAuthority(value)
		if targetPort == "" {
			targetPort = incomingPort
		}
		result.Host = joinAuthority(prefix+targetHost, targetPort)
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
