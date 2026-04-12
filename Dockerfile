# Build stage
FROM golang:1.26-alpine AS builder

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=development
RUN go build -ldflags "-X main.version=${VERSION}" -o /go-philter .

# Run stage
FROM alpine:3.19

# Install openssl to generate self-signed certificate
RUN apk add --no-cache openssl

WORKDIR /

# Copy the binary from the build stage
COPY --from=builder /go-philter /go-philter

# Generate self-signed certificate
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost"

# Expose port 8080
EXPOSE 8080

# Environment variables for TLS
ENV PHILTER_CERT_FILE=/cert.pem
ENV PHILTER_KEY_FILE=/key.pem

# Run the application
ENTRYPOINT ["/go-philter"]
