FROM golang:1.24-alpine AS builder

WORKDIR /app/word_filter_service

COPY ./word_filter_service/go.mod ./word_filter_service/go.sum ./
RUN go mod download

COPY /word_filter_service .

RUN go build -o main cmd/main.go

EXPOSE 8082

CMD ["./main"]