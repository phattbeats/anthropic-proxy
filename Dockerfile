FROM node:22-alpine
WORKDIR /app
COPY anthropic-proxy.js .
EXPOSE 4010

# Health check — the /health endpoint is already implemented in the proxy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:4010/health || exit 1

CMD ["node", "anthropic-proxy.js", "4010"]
