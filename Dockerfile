FROM docker.io/library/golang:1.26

WORKDIR /src
COPY . .
RUN go install ./cmd/httpd

WORKDIR /go
CMD ["httpd", "--help"]
