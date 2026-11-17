ARG BUILD_FROM
# python:3.12-alpine carries the interpreter + CA bundle, so the build is a
# single copy layer — no apk, no git, nothing to compile on a 1 GB Pi.
FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 \
    LANG=C.UTF-8

WORKDIR /app
COPY app/ps4jb.py /app/ps4jb.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh

CMD [ "/run.sh" ]
