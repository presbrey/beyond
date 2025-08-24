package beyond

import (
	"encoding/json"
	"flag"
	"fmt"
	"strings"
)

var (
	hostsCSV    = flag.String("hosts-csv", "", "rewrite nexthop hosts (format: from1=to1,from2=to2)")
	hostsURL    = flag.String("hosts-url", "", "URL to host mapping config (eg. https://github.com/myorg/beyond-config/main/raw/hosts.json)")
	hostsOnly   = flag.Bool("hosts-only", false, "only allow requests to hosts in the host mapping")
	hostsMap    = map[string]string{}
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

func hostRewrite(host string) string {
	if len(hostsMap) == 0 {
		return host
	}
	for k, v := range hostsMap {
		if strings.HasSuffix(host, k) {
			host = strings.Replace(host, k, v, -1)
		}
	}
	return host
}
