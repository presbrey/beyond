package beyond

import (
	"context"
	"flag"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/olivere/elastic"
	log "github.com/sirupsen/logrus"
)

var (
	// import logrus helpers
	Error      = log.Error
	WithError  = log.WithError
	WithField  = log.WithField
	WithFields = log.WithFields

	logHTTP = flag.Bool("log-http", false, "enable HTTP logging to stdout")
	logJSON = flag.Bool("log-json", false, "use json output (logrus)")
	logXFF  = flag.Bool("log-xff", true, "include X-Forwarded-For in logs")

	logElastic   = flag.String("log-elastic", "", "csv of elasticsearch servers")
	logElasticD  = flag.Duration("log-elastic-interval", time.Second, "how often to commit bulk updates")
	logElasticP  = flag.String("log-elastic-prefix", "beyond", "insert this on the front of elastic indexes")
	logElasticW  = flag.Int("log-elastic-workers", 3, "bulk commit workers")
	logElasticCh = make(chan *elastic.BulkUpdateRequest, 10240)
)

func logSetup() error {
	if *logJSON {
		log.SetFormatter(&log.JSONFormatter{})
	}
	if *logElastic != "" {
		return logElasticSetup(*logElastic)
	}
	return nil
}

func logRoundtrip(resp *http.Response) {
	if !*logHTTP && *logElastic == "" {
		return
	}

	d := map[string]interface{}{
		"date": time.Now().Format(time.RFC3339),
		"user": resp.Request.Header.Get(*headerPrefix + "-User"),

		"useragent": resp.Request.UserAgent(),

		"method": resp.Request.Method,
		"host":   resp.Request.Host,
		"path":   resp.Request.URL.Path,
		"query":  resp.Request.URL.RawQuery,
		"origin": resp.Request.Header.Get("Origin"),

		"code":     resp.StatusCode,
		"len":      resp.ContentLength,
		"location": resp.Header.Get("Location"),
		"proto":    resp.Proto,
		"server":   resp.Header.Get("Server"),
		"type":     resp.Header.Get("Content-Type"),

		// "req.header":  resp.Request.Header,
		// "resp.header": resp.Header,
	}
	if *logXFF {
		d["xff"] = resp.Request.Header.Get("X-Forwarded-For")
	}
	for k, v := range d {
		if v == "" {
			delete(d, k)
		}
	}

	if *logHTTP {
		WithFields(d).Info("HTTP")
	}
	if *logElastic != "" {
		id := uuid.Must(uuid.NewV7()).String()
		elt := elastic.NewBulkUpdateRequest().Index(*logElasticP + "-" + id[:4]).Id(id).Type("http").Doc(d).DocAsUpsert(true)
		logElasticPut(elt, logElasticCh)
	}
}

func logElasticPut(elt *elastic.BulkUpdateRequest, sink chan *elastic.BulkUpdateRequest) {
	select {
	case sink <- elt:
	default:
		log.Println("overflow:", elt)
	}
}

func logElasticSetup(elasticURLs string) error {
	elasticSearch, err := elastic.NewSimpleClient(elastic.SetURL(strings.Split(elasticURLs, ",")...))
	if err == nil {
		for i := 0; i < *logElasticW; i++ {
			go func() {
				bulk := elasticSearch.Bulk()
				logElasticWorker(bulk, *logElasticD)
			}()
		}
	}
	return nil
}

func logElasticWorker(bulk *elastic.BulkService, duration time.Duration) {
	tick := time.NewTicker(duration)
	for {
		select {
		case elt := <-logElasticCh:
			bulk.Add(elt)

		case <-tick.C:
			if bulk.NumberOfActions() < 1 {
				continue
			}
			r, err := bulk.Do(context.Background())
			if err != nil {
				log.Println(err)
			}
			if r == nil {
				continue
			}
			fails := r.Failed()
			if len(fails) > 0 {
				log.Println(len(fails), fails[0].Error)
			}
		}
	}
}
