# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM python:3.11-slim AS test
WORKDIR /src
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
COPY tests tests
COPY scripts scripts
COPY demo/oidc.json demo/oidc.json
RUN pip install --no-cache-dir ".[dev]" && pytest

FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
RUN pip install --no-cache-dir .
COPY scripts scripts
# The demo, and with it tlsCa's file: demo/generated/idp-ca.pem, the iya-sts
# listener CA trust chain scripts/configure_iya_sts.py saved. The image trusts
# that iya-sts with no bind mount and no fetch. Rebuild after running the
# install script against a different iya-sts.
# .dockerignore admits that one file from demo/generated (never the client
# secret or a key). A COPY of the demo DIRECTORY succeeds with or without it,
# so a fresh clone and CI still build; naming the file, or a glob that
# matches nothing, fails the build in both builders.
COPY demo demo
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ['PORT']+'/healthz').read()" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "demo/app.py"]
