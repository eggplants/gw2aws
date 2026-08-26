FROM mcr.microsoft.com/playwright/python:v1.61.0-noble@sha256:a9731514f24121d1dcd25d58d0a38146646d290a5998fd80d3e533e7b5e21c69

ARG VERSION
ENV VERSION=${VERSION:-master}

RUN python -m pip install --no-cache-dir git+https://github.com/eggplants/gw2aws@${VERSION} \
    && playwright install chromium

ENTRYPOINT ["gw2aws"]
