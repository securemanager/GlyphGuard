# Dockerfile for GlyphGuard

# Base image with Go installed
FROM golang:1.21-alpine

# Metadata
LABEL maintainer="Ashkan Ebrahimi | O & TM Secure Manager Co"
LABEL version="0.1.0"
LABEL description="GlyphGuard - IDN Homograph Detector"

# Set environment
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    APP_NAME=glyphguard

# Create workdir
WORKDIR /app

# Copy Go module files and source
COPY go.mod go.sum ./
RUN go mod download

COPY glyphguard.go ./

# Build the binary
RUN go build -o $APP_NAME glyphguard.go

# Create logs directory
RUN mkdir -p /var/log/dns

# Expose ports if needed (ELK / Syslog is usually external)
# EXPOSE 9200

# Set entrypoint
ENTRYPOINT ["/app/glyphguard"]

# Default arguments (can override with docker run flags)
CMD ["-log", "/var/log/dns/queries.log", "-elk", "http://elk:9200/glyphguard/_doc/"]
