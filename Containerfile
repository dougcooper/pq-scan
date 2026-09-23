# Alpine 3.24 ships OpenSSL 3.5. TLS PQ verdicts require OpenSSL 3.5+; older
# versions cannot offer ML-KEM groups and probe as UNKNOWN-CLIENT-NO-PQ.
FROM alpine:3.24

COPY pq-cloud-scan.sh targets.tsv /opt/pq-scan/

# Alpine has no bash, so install it (and TLS root certificates) first.
# Then let the script install the rest of its own tools (--setup --yes).
# CFLAGS=-std=gnu11: without it, ike-scan fails to compile on musl.
# Last, remove the build tools and caches to shrink the image from ~545 MB to ~184 MB.
RUN chmod +x /opt/pq-scan/pq-cloud-scan.sh && \
    apk add --no-cache bash ca-certificates && \
    CFLAGS=-std=gnu11 /opt/pq-scan/pq-cloud-scan.sh --setup --yes && \
    apk del build-base autoconf automake git openssl-dev >/dev/null 2>&1; \
    rm -rf /root/.local/src /root/.cache /var/cache/apk/*

# Scans write their results (results.tsv, results.json, ...) to the current
# directory, so run with -v "$PWD":/scan to collect them on the host.
WORKDIR /scan

ENTRYPOINT ["/opt/pq-scan/pq-cloud-scan.sh"]