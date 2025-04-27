FROM golang:1.24-alpine AS builder

WORKDIR /app/identity_service

COPY ./identity_service/go.mod ./identity_service/go.sum ./
RUN go mod download

COPY /identity_service .

RUN go build -o main cmd/main.go

FROM alpine:latest

WORKDIR /root/

COPY --from=builder /app/main .

EXPOSE 8081

CMD ["./main"]