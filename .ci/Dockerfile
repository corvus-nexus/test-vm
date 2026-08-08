ARG ODOO_VERSION=19.0
FROM odoo:${ODOO_VERSION} AS wheel-builder

USER root
# Odoo already supplies its supported psycopg2/PostgreSQL runtime packages.
# Custom requirements must not replace that driver or mix Ubuntu development
# headers with the newer PGDG libpq5 installed by the upstream image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY .ci/requirements.txt /tmp/requirements.txt
RUN python3 -m pip wheel --wheel-dir /tmp/wheels --requirement /tmp/requirements.txt

FROM odoo:${ODOO_VERSION} AS addon-export
ARG ODOO_VERSION
ARG GIT_SHA=unknown
USER root
# BuildKit bind mounts are read-only unless rw/readwrite is requested. Keep the
# complete build context out of this stage's filesystem snapshot while the
# scanner copies only validated addon output into the persisted export tree.
RUN --mount=type=bind,source=.,target=/opt/source \
    install -d /opt/export/addons \
    && python3 /opt/source/.ci/scan_addons.py \
      --root /opt/source \
      --odoo-version "$ODOO_VERSION" \
      --git-sha "$GIT_SHA" \
      --copy-to /opt/export/addons \
      --output /opt/export/odoo-addon-manifest.json \
    && printf '%s\n' "$GIT_SHA" > /opt/export/odoo_image_sha.txt

FROM odoo:${ODOO_VERSION}
ARG ODOO_VERSION

USER root
# Both commands are supplied by the upstream Odoo image. Fail clearly if that
# contract changes instead of mutating the runtime package set unnecessarily.
RUN command -v curl >/dev/null && command -v psql >/dev/null
COPY --from=wheel-builder /tmp/wheels /tmp/wheels
# The upstream image contains Debian-owned Python packages without pip RECORD
# files. Overlay the complete wheel set without trying to uninstall OS packages.
RUN if find /tmp/wheels -maxdepth 1 -type f -name '*.whl' -print -quit | grep -q .; then \
      python3 -m pip install --no-cache-dir --break-system-packages --ignore-installed /tmp/wheels/*.whl; \
    fi \
    && rm -rf /tmp/wheels

ARG GIT_SHA=unknown
ARG BUILD_DATE=unknown
ARG SOURCE_URL=unknown
LABEL org.opencontainers.image.revision="${GIT_SHA}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="${SOURCE_URL}"

COPY --from=addon-export --chown=odoo:odoo /opt/export/addons/ /opt/addons/
COPY --from=addon-export --chown=odoo:odoo /opt/export/odoo-addon-manifest.json /etc/odoo-addon-manifest.json
COPY --from=addon-export --chown=odoo:odoo /opt/export/odoo_image_sha.txt /etc/odoo_image_sha.txt

USER odoo
