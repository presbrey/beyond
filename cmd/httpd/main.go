package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"github.com/presbrey/beyond"
)

var (
	bind = flag.String("http", ":80", "listen address")

	srvReadTimeout  = flag.Duration("server-read-timeout", 1*time.Minute, "max duration for reading the entire request, including the body")
	srvWriteTimeout = flag.Duration("server-write-timeout", 2*time.Minute, "max duration before timing out writes of the response")
	srvIdleTimeout  = flag.Duration("server-idle-timeout", 3*time.Minute, "max time to wait for the next request when keep-alives are enabled")
)

func main() {
	flag.Parse()

	if err := beyond.Setup(); err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:    *bind,
		Handler: beyond.NewMux(),

		// https://blog.cloudflare.com/exposing-go-on-the-internet/
		ReadTimeout:  *srvReadTimeout,
		WriteTimeout: *srvWriteTimeout,
		IdleTimeout:  *srvIdleTimeout,
	}
	log.Fatal(srv.ListenAndServe())
}
