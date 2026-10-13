# Build stage.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/sleepy-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o /out/sleepy-client ./cmd/client

# Runtime stage (server only; the client is a local tool).
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sleepy-server /usr/local/bin/sleepy-server
EXPOSE 443
ENTRYPOINT ["/usr/local/bin/sleepy-server"]
