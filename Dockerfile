FROM --platform=$BUILDPLATFORM golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d AS build

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
