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
RUN pip install --no-cache-dir ".[dev]" && pytest

FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE VERSION ./
COPY src src
RUN pip install --no-cache-dir .
COPY demo demo
COPY scripts scripts
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ['PORT']+'/healthz').read()" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "demo/app.py"]
