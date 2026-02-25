FROM golang:1.23 AS web

WORKDIR /app

COPY go.* ./

RUN go mod download

COPY .env .env

COPY pkg ./pkg
COPY internal ./internal
COPY cmd/web ./cmd/web

RUN go build -v -o /app/web ./cmd/web/main.go

EXPOSE 8888

CMD ["/app/web"]