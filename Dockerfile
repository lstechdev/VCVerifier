FROM golang:1.18-alpine AS build

WORKDIR /go/src/app
COPY ./ ./

RUN apk add build-base

RUN go get -d -v ./...
RUN go generate ./ent
RUN go build -v .

FROM golang:1.18-alpine

WORKDIR /go/src/app
COPY --from=build /go/src/app/back/views /go/src/app/back/views
COPY --from=build /go/src/app/back/www /go/src/app/back/www
COPY --from=build /go/src/app/configs /go/src/app/configs
COPY --from=build /go/src/app/vcbackend /go/src/app/vcbackend
COPY --from=build /go/src/app/vault/templates /go/src/app/vault/templates

CMD ["./vcbackend"]