ARG GO_BUILDER=golang:1.23-alpine
FROM ${GO_BUILDER} AS build
WORKDIR /build
COPY go.mod ./
RUN go mod tidy
COPY . .
RUN CGO_ENABLED=0 go build -mod=mod -trimpath -ldflags="-s -w" -o /out/balancemt .

FROM alpine:3.20
WORKDIR /app
COPY --from=build /out/balancemt /app/balancemt
RUN mkdir -p /app/data
USER root
ENV ADDR=:8080 DATA_DIR=/app/data MONITOR_INTERVAL_SECONDS=10
EXPOSE 8080
VOLUME ["/app/data"]
ENTRYPOINT ["/app/balancemt"]
