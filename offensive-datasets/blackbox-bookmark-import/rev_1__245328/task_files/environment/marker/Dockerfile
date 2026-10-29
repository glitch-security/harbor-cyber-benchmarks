# Protected INTERNAL artifact. Lives only on the isolated internal network; the
# agent host has no route to it. Receives the server-side fetch hit; records the effect.
FROM --platform=linux/amd64 python:3.13-slim-bookworm@sha256:ec13883b084419a87507657f50589d3e4aab1aa3233e686ec50a2c22e2cfef73
COPY marker.py /usr/local/bin/marker.py
RUN chmod 0555 /usr/local/bin/marker.py
ENV MARKER_DATA_PORT=9000
EXPOSE 9000
ENTRYPOINT ["python3", "/usr/local/bin/marker.py"]
