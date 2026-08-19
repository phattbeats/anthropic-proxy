FROM node:22-alpine
WORKDIR /app
# Run as the unprivileged `node` user shipped with the base image. The proxy
# only needs to bind a high port and read its own files; root is unnecessary
# and a hardening miss (PHA-1844 audit, L1).
COPY --chown=node:node anthropic-proxy.js billing-mode.js ./
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

# PHA-1825: bake PROXY_MODE=billing into the image so a recreate that
# drops orchestrator env (docker compose env, unraid template, k8s configmap)
# can't silently fall back to PROXY_MODE=regular. In non-billing mode,
# `oauthHeaders()` (anthropic-proxy.js) uses a hardcoded 4-beta list WITHOUT
# `extended-cache-ttl-2025-04-11` — every cache write then 5m-fallbacks with
# no error and no log line. Shipping the default makes the silent-fallback
# class of bug structurally impossible on fresh deployments. Orchestrator
# `-e PROXY_MODE=...` and `docker run --env-file` still override at run time.
ENV PROXY_MODE=billing

CMD ["node", "anthropic-proxy.js", "4010"]
