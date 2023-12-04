FROM golang:1.21-alpine AS build

WORKDIR /go/src/app
COPY ./api ./api
COPY ./common ./common
COPY ./config ./config
COPY ./docs ./docs
COPY ./gaiax ./gaiax
COPY ./logging ./logging
COPY ./openapi ./openapi
COPY ./ssikit ./ssikit
COPY ./tir ./tir
COPY ./verifier ./verifier
COPY ./views ./views
COPY ./go.mod ./go.mod
COPY ./go.sum ./go.sum
COPY ./health.go ./health.go
COPY ./main.go ./main.go

RUN apk add build-base

RUN go get -d -v ./...
RUN go build -v .

COPY ./key.tls ./key.tls
COPY ./server.yaml ./server.yaml
COPY ./credentials.json ./credentials.json

FROM golang:1.21-alpine

WORKDIR /go/src/app

COPY --from=build /go/src/app/key.tls /config/tls.key
COPY --from=build /go/src/app/server.yaml /config/server.yaml
COPY --from=build /go/src/app/credentials.json /config/credential.json

COPY --from=build /go/src/app/views /go/src/app/views
COPY --from=build /go/src/app/VCVerifier /go/src/app/VCVerifier
COPY --from=build /go/src/app/server.yaml /go/src/app/server.yaml

CMD ["./VCVerifier"]