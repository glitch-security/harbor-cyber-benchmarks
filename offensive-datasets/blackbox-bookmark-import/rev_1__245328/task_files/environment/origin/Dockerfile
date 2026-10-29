# Attacker-controlled "public" origin. Serves on the public-class network the
# target can reach (so Karakeep's validateUrl accepts it); admin surface on a
# separate port for the operator/agent/verifier to program its responses.
FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:ec13883b084419a87507657f50589d3e4aab1aa3233e686ec50a2c22e2cfef73
COPY origin.py /usr/local/bin/origin.py
RUN chmod 0555 /usr/local/bin/origin.py
ENV ORIGIN_DATA_PORT=8080 ORIGIN_ADMIN_PORT=8090
EXPOSE 8080 8090
ENTRYPOINT ["python3", "/usr/local/bin/origin.py"]
