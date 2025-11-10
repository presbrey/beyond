package authz

import (
	"encoding/json"
	"flag"
	"net/http"
	"path"
	"sync"
)

var (
	FenceURL     = flag.String("fence-url", "", "URL to user fencing config (eg. https://github.com/myorg/beyond-config/main/raw/fence.json)")
	SitesURL     = flag.String("sites-url", "", "URL to allowed sites config (eg. https://github.com/myorg/beyond-config/main/raw/sites.json)")
	AllowlistURL = flag.String("allowlist-url", "", "URL to site allowlist (eg. https://github.com/myorg/beyond-config/main/raw/allowlist.json)")

	fence     = concurrentMapMapBool{m: map[string]map[string]bool{}}
	sites     = concurrentMapMapBool{m: map[string]map[string]bool{}}
	allowlist = concurrentMapMapBool{m: map[string]map[string]bool{}}

	httpACL = &http.Client{}
)

type concurrentMapMapBool struct {
	sync.RWMutex
	m map[string]map[string]bool
}

// SetHTTPClient sets the HTTP client for ACL operations (useful for testing)
func SetHTTPClient(client *http.Client) {
	httpACL = client
}

// RefreshFence loads the user fencing configuration
func RefreshFence() error {
	if *FenceURL == "" {
		return nil
	}

	resp, err := httpACL.Get(*FenceURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	d := map[string][]string{}
	err = json.NewDecoder(resp.Body).Decode(&d)
	if err != nil {
		return err
	}
	for k, v := range d {
		if _, ok := fence.m[k]; !ok {
			fence.m[k] = map[string]bool{}
		}
		for _, v := range v {
			fence.m[k][v] = true
		}
	}
	return nil
}

// RefreshSites loads the allowed sites configuration
func RefreshSites() error {
	if *SitesURL == "" {
		return nil
	}

	resp, err := httpACL.Get(*SitesURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	d := map[string][]string{}
	err = json.NewDecoder(resp.Body).Decode(&d)
	if err != nil {
		return err
	}
	sites.Lock()
	defer sites.Unlock()
	for k, v := range d {
		if _, ok := sites.m[k]; !ok {
			sites.m[k] = map[string]bool{}
		}
		for _, v := range v {
			sites.m[k][v] = true
		}
	}
	return nil
}

// RefreshAllowlist loads the site allowlist configuration
func RefreshAllowlist() error {
	if *AllowlistURL == "" {
		return nil
	}

	resp, err := httpACL.Get(*AllowlistURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	allowlist.Lock()
	defer allowlist.Unlock()
	return json.NewDecoder(resp.Body).Decode(&allowlist.m)
}

// Allowlisted checks if a request is on the allowlist
func Allowlisted(r *http.Request) bool {
	allowlist.RLock()
	allow := allowlist.m["host"][r.Host]
	hostM := allowlist.m["host:method"][r.Host+":"+r.Method]
	paths := allowlist.m["path"]
	allowlist.RUnlock()
	if allow || hostM {
		return true
	}
	p := path.Clean(r.URL.Path)
	for ; p != "/"; p = path.Dir(p) {
		if paths[p] {
			allow = true
		}
	}
	return allow
}

// Deny checks if a user is denied access based on fence and sites configuration
func Deny(r *http.Request, user string) bool {
	fence.RLock()
	zones, ok := fence.m[user]
	fence.RUnlock()

	if !ok || len(zones) < 1 {
		return false
	}

	sites.RLock()
	m := sites.m
	sites.RUnlock()

	for k := range zones {
		if m[k]["https://"+r.Host] || m[k]["http://"+r.Host] {
			return false
		}
	}
	return true
}

// GetSitesURLs returns all site URLs for proxy configuration
func GetSitesURLs(fn func(siteURL string)) {
	sites.RLock()
	defer sites.RUnlock()
	for _, v := range sites.m {
		for x := range v {
			fn(x)
		}
	}
}

// GetSitesMap returns the sites map for a given key (for testing)
func GetSitesMap(key string) map[string]bool {
	sites.RLock()
	defer sites.RUnlock()
	return sites.m[key]
}

// SetSitesMap sets the sites map for a given key (for testing)
func SetSitesMap(key string, value map[string]bool) {
	sites.Lock()
	defer sites.Unlock()
	sites.m[key] = value
}
