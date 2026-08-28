FROM python:3.12-slim-bookworm

ARG APP_UID=10001
ARG APP_GID=10001

RUN set -eu; \
    groupadd --gid "${APP_GID}" crownfall; \
    useradd --uid "${APP_UID}" --gid "${APP_GID}" \
      --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin crownfall; \
    install -d -o root -g root -m 0755 /opt/crownfall

COPY --chown=root:root crownfall_target.py /opt/crownfall/crownfall_target.py

RUN chmod 0555 /opt/crownfall/crownfall_target.py

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CROWNFALL_BIND=0.0.0.0 \
    CROWNFALL_PORT=8785

EXPOSE 8785/tcp
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=2s --timeout=2s --start-period=3s --retries=15 \
  CMD ["python3", "-c", "import json,os,urllib.request; p=os.environ.get('CROWNFALL_PORT','8785'); r=urllib.request.urlopen('http://127.0.0.1:'+p+'/manifest?challenge='+'0'*32,timeout=1); assert r.status==200 and json.load(r)['service']=='crownfall-disposable-target'"]

ENTRYPOINT ["python3", "/opt/crownfall/crownfall_target.py"]
