FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
	-trimpath \
	-ldflags="-s -w -X main.version=${VERSION}" \
	-o /out/sshgate .
RUN mkdir -p /data

FROM scratch
COPY --from=build /out/sshgate /sshgate
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=65532:65532 /data /var/lib/sshgate
USER 65532:65532
VOLUME ["/var/lib/sshgate"]
ENTRYPOINT ["/sshgate"]
CMD ["serve"]
