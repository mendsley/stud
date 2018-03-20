FROM alpine:3.7 AS builder

RUN apk add --update \
		bsd-compat-headers \
		gcc \
		libev-dev \
		make \
		musl-dev \
		openssl-dev \
		;

ADD . /usr/src/stud/
RUN make -C /usr/src/stud/

FROM alpine:3.7
LABEL maintainer="Matthew Endsley <mendsley@gmail.com>"

RUN apk add --update \
		openssl=1.0.2n-r0 \
		libev=4.24-r0 \
	&& rm -rf /var/cache/apk/* \
	&& mkdir -p /cert /sock \
	;

COPY --from=builder /usr/src/stud/stud /usr/bin/stud

EXPOSE 443

ENTRYPOINT ["/usr/bin/stud"]
CMD ["-q", "--write-proxy-v2", "/cert/stud.pem", "--ciphers", "ECDH-AESGCM:DH+AWSGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDG+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS:TLS_FALLBACK_SCSV"]
