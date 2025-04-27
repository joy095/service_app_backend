FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY ./api_gateway/go.mod ./api_gateway/go.sum ./
RUN go mod download

COPY ./api_gateway .

RUN go build -o main ./cmd/main.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 8080

CMD ["./main"]