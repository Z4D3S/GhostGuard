# Build stage
FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ghostguard ./cmd/ghostguard

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/ghostguard /usr/local/bin/ghostguard
COPY --from=builder /app/policies /app/policies

EXPOSE 8081

ENTRYPOINT ["ghostguard"]
CMD ["serve", "--port", "8081", "--policies", "/app/policies"]
