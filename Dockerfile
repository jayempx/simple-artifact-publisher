FROM node:26-alpine
WORKDIR /app
ARG BUILD_SHA
ENV BUILD_SHA=$BUILD_SHA
COPY server.mjs .
USER node
EXPOSE 8080
CMD ["node", "server.mjs"]
