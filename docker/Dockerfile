FROM docker.io/golang:1.24-alpine3.22 AS builder


ENV CFLAGS="-march=native -Ofast"
ENV CXXFLAGS="-march=native -Ofast"
ENV LDFLAGS="-flto -fpie"
ENV CGO_CFLAGS="-march=native -Ofast"

RUN apk update && apk add --no-cache \
    git gcc g++ musl-dev bash autoconf automake cmake make libtool gettext

RUN git clone --depth 1 --branch v1.2.1 https://github.com/tevador/RandomX.git /tmp/RandomX && cd /tmp/RandomX && \
    mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release -D CMAKE_INSTALL_PREFIX:PATH=/usr && \
    make -j$(nproc) && \
    make install && \
    cd ../ && \
    rm -rf /tmp/RandomX

WORKDIR /src

ARG GOPROXY=""
ENV GOPROXY=${GOPROXY}
ARG GOAMD64=""
ENV GOAMD64=${GOAMD64}

COPY go.mod go.sum ./
RUN go mod download -x && go mod verify

COPY . .

ENV CGO_ENABLED=0
RUN go build \
    -tags=purego,netgo -trimpath -v -pgo=auto \
    -ldflags="-buildid= -bindnow -extldflags '-static'" -buildmode exe \
    -o /usr/bin/dns-checkpoints ./cmd/dns-checkpoints

ENV CGO_ENABLED=1
RUN go build \
    -tags=enable_randomx_library -trimpath -v -pgo=auto \
    -ldflags="-buildid= -bindnow -linkmode external -extldflags '-static'" -buildmode exe \
    -o /usr/bin/highway ./cmd/highway



FROM docker.io/alpine:3.22

ARG BUILD_BINARY

COPY --from=builder /usr/bin/${BUILD_BINARY} /usr/bin/${BUILD_BINARY}

WORKDIR /data