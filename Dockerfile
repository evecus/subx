# syntax=docker/dockerfile:1
FROM node:20-alpine AS frontend
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm ci --no-audit --no-fund
COPY web/ .
RUN npm run build

FROM rust:1.85-alpine AS backend
WORKDIR /src
RUN apk add --no-cache build-base perl ca-certificates
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY web/dist ./web/dist
RUN cargo build --release --locked

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
ENV data_dir=/app/data
COPY --from=backend /src/target/release/subx /app/subx
EXPOSE 3000
VOLUME ["/app/data"]
ENTRYPOINT ["/app/subx"]
