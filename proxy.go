package beyond

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/presbrey/beyond/internal/authz"

	"github.com/koding/websocketproxy"
)

var (
	hostProxy = sync.Map{}
)

func http2ws(r *http.Request) (*url.URL, error) {
	rewrite := authz.HostRewriteDetailed(r.Host)

	if rewrite.FullURL != "" {
		target, err := url.Parse(rewrite.FullURL)
		if err != nil {
			return nil, err
		}
		if target.Scheme == "https" {
			target.Scheme = "wss"
		} else {
			target.Scheme = "ws"
		}
		target.RawPath = strings.TrimSuffix(target.EscapedPath(), "/") + r.URL.EscapedPath()
		target.Path = strings.TrimSuffix(target.Path, "/") + r.URL.Path
		if target.RawQuery != "" && r.URL.RawQuery != "" {
			target.RawQuery += "&" + r.URL.RawQuery
		} else {
			target.RawQuery += r.URL.RawQuery
		}
		return target, nil
	}
	return url.Parse("wss://" + rewrite.Host + r.URL.RequestURI())
}

func nexthop(w http.ResponseWriter, r *http.Request) {
	var (
		rewrite   = authz.HostRewriteDetailed(r.Host)
		nextHost  = rewrite.Host
		nextProxy http.Handler
	)

	// Use full URL if available for backend connection
	var targetBase string
	if rewrite.FullURL != "" {
		targetBase = rewrite.FullURL
	} else {
		targetBase = nextHost
	}

	v, ok := hostProxy.Load(targetBase)
	if ok {
		nextProxy, ok = v.(*httputil.ReverseProxy)
	}
	if !ok && *learnNexthops {
		nextProxy = learn(targetBase)
		if nextProxy != nil {
			hostProxy.Store(targetBase, nextProxy)
			ok = true
		}
	}

	if !ok || nextProxy == nil {
		// unconfigured
		errorHandler(w, 404, *fouroFourMessage)
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		var err error
		nextProxy, err = websocketproxyNew(r)
		if err != nil {
			errorHandler(w, http.StatusBadGateway, "Invalid WebSocket backend")
			return
		}
	}
	nextProxy.ServeHTTP(w, r)
}

func newSHRP(target *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(target)
	p.ModifyResponse = func(resp *http.Response) error {
		logRoundtrip(resp)
		return nil
	}
	return p
}

func reproxy() error {
	cleanup := map[string]bool{}
	hostProxy.Range(func(key interface{}, value interface{}) bool {
		if key, ok := key.(string); ok {
			cleanup[key] = true
		}
		return true
	})
	var lerr error
	authz.GetSitesURLs(func(x string) {
		u, err := url.Parse(x)
		if err != nil {
			lerr = err
		} else {
			p := newSHRP(u)
			for _, key := range []string{u.Host, u.String()} {
				delete(cleanup, key)
				hostProxy.Store(key, p)
			}
		}
	})
	for key := range cleanup {
		hostProxy.Delete(key)
	}
	return lerr
}

func websocketproxyDirector(incoming *http.Request, out http.Header) {
	out.Set("User-Agent", incoming.UserAgent())
	out.Set("X-Forwarded-Proto", "https")
}

func websocketproxyNew(r *http.Request) (*websocketproxy.WebsocketProxy, error) {
	ws, err := http2ws(r)
	if err != nil {
		return nil, err
	}
	if ws.Host == "" {
		return nil, fmt.Errorf("missing WebSocket backend host")
	}
	p := websocketproxy.NewProxy(ws)
	p.Director = websocketproxyDirector
	return p, err
}

func websocketproxyCheckOrigin(r *http.Request) bool {
	return true
}
