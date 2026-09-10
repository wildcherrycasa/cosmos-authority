# Cosmos — zero runtime dependencies, so this is just Node and the source.
FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY api ./api
COPY core ./core
COPY mcp ./mcp
COPY scripts ./scripts
# The event log lives here; mount a volume so it survives the container.
VOLUME ["/app/data"]
ENV NODE_ENV=production
ENV PORT=8787
# REQUIRED at run time (see `npm run keygen`): COSMOS_RECEIPT_KID, COSMOS_RECEIPT_PRIVATE_KEY.
# With NODE_ENV=production and no key, the server refuses to start rather than signing with a dev key.
EXPOSE 8787
CMD ["node", "api/server.js"]
