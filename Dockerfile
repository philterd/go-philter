# Build stage
FROM golang:1.26-alpine AS builder

# Install build tools for CGO, CMake, and GLiNER.cpp
RUN apk add --no-cache build-base git make cmake g++ musl-dev rust cargo tar wget gcompat ca-certificates

# Clone and build GLiNER.cpp to get libgliner
WORKDIR /gliner-cpp
RUN git clone https://github.com/Knowledgator/GLiNER.cpp.git . && \
    git submodule update --init --recursive

RUN wget --no-check-certificate https://github.com/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-linux-x64-1.19.2.tgz && \
    tar -xvzf onnxruntime-linux-x64-1.19.2.tgz

# Navigate into the Rust directory and patch the source code directly
RUN sed -i 's/(\*handle).decode_str.len()/(\&(\*handle).decode_str).len()/g' deps/tokenizers-cpp/rust/src/lib.rs && \
    sed -i 's/(\*handle).id_to_token_result.len()/(\&(\*handle).id_to_token_result).len()/g' deps/tokenizers-cpp/rust/src/lib.rs

RUN cmake . -D BUILD_SHARED_LIBS=ON -D ONNXRUNTIME_ROOTDIR=$(pwd)/onnxruntime-linux-x64-1.19.2 && \
    make -j$(nproc) && \
    cp libgliner.so /usr/local/lib/ && \
    cp gliner.h /usr/local/include/

WORKDIR /app

# Install dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with PhEye support
ARG VERSION=development
RUN go build -tags pheye -ldflags "-X main.version=${VERSION}" -o /go-philter .

# Run stage
FROM alpine:3.19

# Install openssl to generate self-signed certificate and libstdc++ for GLiNER.cpp
RUN apk add --no-cache openssl libstdc++ gcompat

WORKDIR /

# Copy the binary from the build stage
COPY --from=builder /go-philter /go-philter
# Copy libgliner.so and onnxruntime libraries from the build stage
COPY --from=builder /usr/local/lib/libgliner.so /usr/local/lib/libgliner.so
COPY --from=builder /gliner-cpp/onnxruntime-linux-x64-1.19.2/lib/*.so* /usr/local/lib/

# Generate self-signed certificate
RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=localhost"

# Expose port 8080
EXPOSE 8080

# Environment variables for TLS and library path
ENV PHILTER_CERT_FILE=/cert.pem
ENV PHILTER_KEY_FILE=/key.pem
ENV LD_LIBRARY_PATH=/usr/local/lib

# Run the application
ENTRYPOINT ["/go-philter"]
