FROM alpine:3.21 AS binary
ADD ./dist/ssh-gateway-linux-amd64 /usr/local/bin/ssh-gateway
RUN chmod 755 /usr/local/bin/ssh-gateway

FROM alpine:3.21
RUN apk --update --no-cache add ca-certificates && \
    addgroup -g 1001 gateway && \
    adduser -D -u 1001 -G gateway gateway
COPY --from=binary /usr/local/bin/ssh-gateway /usr/local/bin/ssh-gateway
USER gateway
ENTRYPOINT ["/usr/local/bin/ssh-gateway"]
