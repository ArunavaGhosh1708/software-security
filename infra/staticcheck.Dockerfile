FROM golang:1.24.2-bookworm
RUN go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
ENV GOCACHE=/tmp/go-cache GOMODCACHE=/tmp/go-modules GOPROXY=off GOSUMDB=off
ENTRYPOINT ["staticcheck"]
