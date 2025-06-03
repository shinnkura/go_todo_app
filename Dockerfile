# デプロイ用コンテナに含めるバイナリを作成するコンテナ
FROM golang:1.24-bullseye as deploy-builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -trimpath -ldflags "-w -s" -o app

# ---------------------------------------------------
# デプロイ用コンテナ
FROM debian:bullseye-slim as deploy

RUN apt-get update

COPY --from=deploy-builder /app/app .

CMD ["./app"]

# ---------------------------------------------------
# 開発用コンテナ

FROM golang:1.24 as dev
WORKDIR /app
RUN go install github.com/air-verse/air@latest
# 開発用コンテナでは、airコマンドを使用して、ホットリロードを行う
CMD ["air"]