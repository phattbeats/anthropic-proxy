FROM node:22-alpine
WORKDIR /app
COPY anthropic-proxy.js billing-mode.js ./
EXPOSE 4010

# Health check — uses node directly so we don't depend on wget being in alpine
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4010/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"

# PHA-1387 side quest: plumb the proxy version from the release tag so
# /health reports the actual deployed version instead of a hardcoded value.
ARG PROXY_VERSION=unknown
ENV PROXY_VERSION=${PROXY_VERSION}

CMD ["node", "anthropic-proxy.js", "4010"]
