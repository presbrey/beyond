package beyond

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/olivere/elastic"
	"github.com/stretchr/testify/assert"
)

var (
	logElasticTestErrorN = 0
	logElasticTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_bulk":
			rBody, _ := io.ReadAll(r.Body)
			switch {
			case strings.Contains(string(rBody), "ERROR") && logElasticTestErrorN < 5:
				logElasticTestErrorN++
				w.WriteHeader(500)
				fmt.Fprint(w, `{`)
			case strings.Contains(string(rBody), "FAILED"):
				w.WriteHeader(200)
				r := &mockElasticBulkUpdateResponse{}
				r.Items = append(r.Items, mockElasticBulkUpdateResponseItem{})
				r.Items[0].Update.Shards.Failed = 10
				json.NewEncoder(w).Encode(r)
			default:
				w.WriteHeader(200)
				fmt.Fprint(w, `{}`)
			}
		default:
			w.WriteHeader(204)
			log.Printf("ESTEST(%s): %+v\n", r.URL.Path, r)
		}
	}))
)

func init() {
	*logJSON = true
	*logXFF = true

	// cover nil
	*logElastic = ""
	logRoundtrip(nil)
	logSetup()

	*logElastic = logElasticTestServer.URL
	*logElasticD = time.Millisecond
	*logElasticW = 1
}

func TestLogHTTP(t *testing.T) {
	*logHTTP = true

	req, err := http.NewRequest("GET", "/log", nil)
	assert.NoError(t, err)
	resp := &http.Response{Request: req}
	logRoundtrip(resp)
}

func TestLogElasticOverflow(t *testing.T) {
	elt := elastic.NewBulkUpdateRequest()
	ch := make(chan *elastic.BulkUpdateRequest)
	logElasticPut(elt, ch)
}

func TestLogElasticWorker(t *testing.T) {
	time.Sleep(10 * time.Millisecond)
	logElasticCh <- elastic.NewBulkUpdateRequest().Index("FAILED")
	time.Sleep(10 * time.Millisecond)
	logElasticCh <- elastic.NewBulkUpdateRequest().Index("ERROR")
	time.Sleep(10 * time.Millisecond)
}

type mockElasticBulkUpdateResponse struct {
	Took   int                                 `json:"took"`
	Errors bool                                `json:"errors"`
	Items  []mockElasticBulkUpdateResponseItem `json:"items"`
}

type mockElasticBulkUpdateResponseItem struct {
	Update struct {
		Index   string `json:"_index"`
		ID      string `json:"_id"`
		Version int    `json:"_version"`
		Result  string `json:"result"`
		Shards  struct {
			Total      int `json:"total"`
			Successful int `json:"successful"`
			Failed     int `json:"failed"`
		} `json:"_shards"`
		SeqNo       int `json:"_seq_no"`
		PrimaryTerm int `json:"_primary_term"`
		Status      int `json:"status"`
	} `json:"update"`
}
