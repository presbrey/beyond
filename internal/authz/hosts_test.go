package authz

import (
	"flag"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestHostMappingBoundariesAndSpecificity(t *testing.T) {
	oldMap, oldOnly := hostsMap, *HostsOnly
	t.Cleanup(func() { hostsMap = oldMap; *HostsOnly = oldOnly })
	*HostsOnly = true
	hostsMap = map[string]string{"example.com": "https://backend.test:8443", "api.example.com": "http://api.test:8080"}
	for _, tc := range []struct {
		host    string
		allowed bool
		target  string
	}{
		{"example.com", true, "https://backend.test:8443"},
		{"service.example.com", true, "https://service.backend.test:8443"},
		{"EXAMPLE.COM.:443", true, "https://backend.test:8443"},
		{"api.example.com", true, "http://api.test:8080"},
		{"service.api.example.com", true, "http://service.api.test:8080"},
		{"evilexample.com", false, ""},
		{"example.com.evil.test", false, ""},
	} {
		t.Run(tc.host, func(t *testing.T) {
			require.Equal(t, tc.allowed, HostAllowed(tc.host))
			require.Equal(t, tc.target, HostRewriteDetailed(tc.host).FullURL)
		})
	}
}

func TestHostMappingPortsAndLegacyFlag(t *testing.T) {
	oldMap, oldCSV := hostsMap, *HostsCSV
	t.Cleanup(func() { hostsMap = oldMap; *HostsCSV = oldCSV })
	hostsMap = map[string]string{}
	require.NoError(t, flag.Set("host-masq", "old.test=new.test"))
	require.NoError(t, HostsSetup(*HostsCSV))
	require.Equal(t, "sub.new.test:8080", RewriteHost("sub.old.test:8080"))
	require.NoError(t, HostsSetup("old.test:9443=https://[::1]:8443"))
	require.Equal(t, "https://[::1]:8443", HostRewriteDetailed("old.test:9443").FullURL)
	for _, config := range []string{"=new.test", "old.test=", "old.test=ftp://new.test", "old.test=https://"} {
		require.Error(t, HostsSetup(config))
	}
}

func TestMoreSpecificHostnameWinsOverParentPort(t *testing.T) {
	oldMap := hostsMap
	t.Cleanup(func() { hostsMap = oldMap })
	hostsMap = map[string]string{"example.com:12345": "https://parent.test", "api.example.com": "https://api.test"}
	require.Equal(t, "https://api.test", HostRewriteDetailed("api.example.com:12345").FullURL)
}
