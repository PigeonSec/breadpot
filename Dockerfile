# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o breadcrumb-pot cmd/breadcrumb-pot/main.go

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/breadcrumb-pot .

# Copy configuration and templates
COPY config.yaml .
COPY templates/ templates/

# Create logs directory
RUN mkdir -p logs

# Expose ports
EXPOSE 8080 53/udp 53/tcp 22 23 21 25 3306

# Run as non-root user for security
RUN adduser -D -u 1000 honeypot && \
    chown -R honeypot:honeypot /app

USER honeypot

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/_health || exit 1

# Default command
ENTRYPOINT ["./breadcrumb-pot"]
CMD ["-config", "config.yaml"]
