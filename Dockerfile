# Build stage
FROM golang:1.26-bookworm AS builder

# Install build tools for CGO, CMake, and GLiNER.cpp
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    make \
    cmake \
    g++ \
    tar \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install modern Rust using rustup
RUN wget -qO- https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Clone and build GLiNER.cpp to get libgliner
WORKDIR /gliner-cpp
RUN git clone https://github.com/Knowledgator/GLiNER.cpp.git . && \
    git submodule update --init --recursive

RUN wget --no-check-certificate https://github.com/microsoft/onnxruntime/releases/download/v1.19.2/onnxruntime-linux-x64-1.19.2.tgz && \
    tar -xvzf onnxruntime-linux-x64-1.19.2.tgz

# Navigate into the Rust directory and patch the source code directly
RUN sed -i 's/(\*handle).decode_str.len()/(\&(\*handle).decode_str).len()/g' deps/tokenizers-cpp/rust/src/lib.rs && \
    sed -i 's/(\*handle).id_to_token_result.len()/(\&(\*handle).id_to_token_result).len()/g' deps/tokenizers-cpp/rust/src/lib.rs

RUN cmake . -D BUILD_SHARED_LIBS=OFF -D ONNXRUNTIME_ROOTDIR=$(pwd)/onnxruntime-linux-x64-1.19.2 && \
    cmake --build . -- -j$(nproc)

RUN find /gliner-cpp -name 'libgliner.a' -exec cp {} /usr/local/lib/ \;
RUN find /gliner-cpp -name 'gliner.h' -exec cp {} /usr/local/include/ \;
RUN test -f /usr/local/include/gliner.h || (find /gliner-cpp -name 'gliner*' && exit 1)
RUN cp /gliner-cpp/onnxruntime-linux-x64-1.19.2/lib/*.so* /usr/local/lib/

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
FROM ubuntu:24.04

# Install openssl to generate self-signed certificate and dependencies for GLiNER.cpp
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libstdc++6 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy the binary from the build stage
COPY --from=builder /go-philter /go-philter
# Copy libgliner.a and onnxruntime libraries from the build stage
COPY --from=builder /usr/local/lib/libgliner.a /usr/local/lib/libgliner.a
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
