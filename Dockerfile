FROM node:22-alpine
WORKDIR /app
COPY anthropic-proxy.js .
EXPOSE 4010
CMD ["node", "anthropic-proxy.js", "4010"]
