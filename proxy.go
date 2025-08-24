package beyond

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/koding/websocketproxy"
)

var (
	hostProxy = sync.Map{}
)

func http2ws(r *http.Request) (*url.URL, error) {
	rewrite := hostRewriteDetailed(r.Host)
	
	var target string
	if rewrite.FullURL != "" {
		// Convert http/https to ws/wss for WebSocket
		if rewrite.Scheme == "https" {
			target = "wss://" + rewrite.Host
			if rewrite.Port != "" {
				target += ":" + rewrite.Port
			}
		} else {
			target = "ws://" + rewrite.Host
			if rewrite.Port != "" {
				target += ":" + rewrite.Port
			}
		}
		target += r.URL.RequestURI()
	} else {
		// Default to secure WebSocket
		target = "wss://" + rewrite.Host + r.URL.RequestURI()
	}
	return url.Parse(target)
}

func nexthop(w http.ResponseWriter, r *http.Request) {
	var (
		rewrite   = hostRewriteDetailed(r.Host)
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

	v, ok := hostProxy.Load(nextHost)
	if ok {
		nextProxy, ok = v.(*httputil.ReverseProxy)
	}
	if !ok && *learnNexthops {
		nextProxy = learn(targetBase)
		if nextProxy != nil {
			hostProxy.Store(nextHost, nextProxy)
			ok = true
		}
	}

	if !ok || nextProxy == nil {
		// unconfigured
		errorHandler(w, 404, *fouroFourMessage)
		return
	}

	if r.Header.Get("Upgrade") == "websocket" {
		nextProxy, _ = websocketproxyNew(r)
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
	sites.RLock()
	for _, v := range sites.m {
		for x := range v {
			u, err := url.Parse(x)
			if err != nil {
				lerr = err
			} else {
				delete(cleanup, u.Host)
				hostProxy.Store(u.Host, newSHRP(u))
			}
		}
	}
	sites.RUnlock()
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
	p := websocketproxy.NewProxy(ws)
	p.Director = websocketproxyDirector
	return p, err
}

func websocketproxyCheckOrigin(r *http.Request) bool {
	return true
}
