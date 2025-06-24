FROM golang:1.18.1

ADD . /go/src/github.com/presbrey/beyond
WORKDIR /go/src/github.com/presbrey/beyond
RUN go install ./cmd/httpd

WORKDIR /go
CMD ["httpd", "--help"]
