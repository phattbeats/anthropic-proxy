FROM node:22-alpine
WORKDIR /app
# Run as the unprivileged `node` user shipped with the base image. The proxy
# only needs to bind a high port and read its own files; root is unnecessary
# and a hardening miss (PHA-1844 audit, L1).
COPY --chown=node:node anthropic-proxy.js billing-mode.js ./

# PHA-2194: the structured JSONL access log (anthropic-proxy.js LOG_FILE) went
# to stdout only, so it died on every container restart. Default it to a
# mounted volume so it survives recreates; created + chowned here because the
# process runs as the unprivileged `node` user and can't mkdir under /var/log
# itself. Unbounded growth is handled by scripts/logrotate-anthropic-proxy
# (mount it into /etc/logrotate.d on the host, or add an external logrotate
# sidecar — Node itself never rotates this file).
RUN mkdir -p /var/log/anthropic-proxy && chown node:node /var/log/anthropic-proxy
ENV LOG_FILE=/var/log/anthropic-proxy/access.jsonl
VOLUME /var/log/anthropic-proxy

USER node
EXPOSE 4010

# Liveness — process is up and serving. Cheap; safe to run often.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4010/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
# Readiness — actively probes upstream so a half-broken pod drops out of LB
# rotation instead of returning 502s to every request (PHA-1844 audit, L2).
# Use a longer timeout than the probe so a slow upstream doesn't false-negative.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=2 \
  CMD node -e "require('http').get('http://localhost:4010/ready',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# PHA-1387 side quest: plumb the proxy version from the release tag so
# /health reports the actual deployed version instead of a hardcoded value.
ARG PROXY_VERSION=unknown
ENV PROXY_VERSION=${PROXY_VERSION}

# PHA-1825: bake PROXY_MODE=billing into the image. Two reasons:
#   1. The proxy's *intended* mode is billing (see billing-mode.js — the entire
#      module exists because the billing path is the production path). Anyone
#      who recreates the container without -e PROXY_MODE=... / an env_file
#      silently lands in PROXY_MODE=regular, which is not the supported
#      default for this image.
#   2. Belt-and-braces. OAUTH_BETAS in anthropic-proxy.js currently carries
#      the extended-cache-ttl-2025-04-11 beta (see PHA-1611), but that fix is
#      a code-level property that a future contributor could regress without
#      breaking tests. Defaulting to billing makes the cache_ttl safety net
#      load-bearing from the image defaults rather than from oauthHeaders().
# Orchestrator -e PROXY_MODE=... and env_file still override at run time.
# This is a default, not a force.
ENV PROXY_MODE=billing

CMD ["node", "anthropic-proxy.js", "4010"]
