# One image, two entrypoints. The admin plane and the ingest worker share a
# codebase and share nothing else: different command, different network,
# different credentials, and only one of them listens.
#
# Building them as one image is deliberate rather than lazy. Two images built
# from the same lockfile that drift apart in dependency versions is a class of
# bug nobody looks for, and the thing that separates these services is their
# runtime capability, not their bytes.

FROM python:3.13-slim-bookworm AS base

# Version-pinned to match the uv that resolved uv.lock. Pin this by digest as
# well before this image is built anywhere that matters: a tag is mutable, and
# this binary is what installs every other dependency.
COPY --from=ghcr.io/astral-sh/uv:0.11.14 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

WORKDIR /app

# Dependencies first, so a source edit does not re-resolve the world.
COPY pyproject.toml uv.lock ./
COPY packages/dist-core/pyproject.toml packages/dist-core/
COPY packages/dist-ingest/pyproject.toml packages/dist-ingest/
COPY packages/dist-registry/pyproject.toml packages/dist-registry/
COPY packages/dist-admin/pyproject.toml packages/dist-admin/
COPY packages/dist-sign/pyproject.toml packages/dist-sign/
COPY bindings/python/pyproject.toml bindings/python/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-install-workspace \
      --package dist-admin --package dist-ingest --package dist-sign

COPY packages/ packages/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --package dist-admin --package dist-ingest --package dist-sign

# Neither service needs to write to its own code, and neither runs as root.
RUN useradd --system --uid 10001 --create-home dist

# Quarantine is the one path the worker writes to, and it is a named volume.
# Creating it here with the right owner is what makes that work: Docker seeds a
# *fresh* named volume from the image's directory, ownership included. A volume
# that already exists keeps whatever it had, so changing this line means
# removing the volume as well.
RUN mkdir -p /srv/quarantine /srv/repo/metadata /srv/repo/targets /srv/keys \
             /var/cache/dist /var/lib/dist \
 && chown 10001:10001 /srv/quarantine /srv/repo /srv/repo/metadata /srv/repo/targets \
                      /srv/keys /var/cache/dist /var/lib/dist

USER 10001

# Last, so changing them does not invalidate the dependency or source layers.
#
# Both default to empty rather than to a placeholder: `dist_core.buildinfo`
# then reports the content digest alone, which needs no build argument and is
# the identifier that actually answers "is this container running my tree".
ARG DIST_BUILD_REF=""
ARG DIST_BUILD_TIME=""
ENV DIST_BUILD_REF=${DIST_BUILD_REF} \
    DIST_BUILD_TIME=${DIST_BUILD_TIME}


FROM base AS admin
EXPOSE 8081
CMD ["python", "-m", "dist_admin"]


FROM base AS worker
# No EXPOSE. This service has no inbound listener, which is the property that
# lets it hold the forge credential (PLAN.md 2).
CMD ["python", "-m", "dist_ingest.worker"]


FROM base AS signer
# No EXPOSE and no network client in its dependencies. This is the only
# component that may write TUF metadata, and it holds the online keys, so the
# set of things that can reach it is kept as close to empty as the runtime
# allows.
CMD ["python", "-m", "dist_sign.worker"]
