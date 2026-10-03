FROM node:22.16.0-bookworm-slim
RUN mkdir -p /opt/eslint && cd /opt/eslint && npm init -y && npm install --save-exact eslint@9.39.1 @typescript-eslint/parser@8.46.1
ENV NODE_PATH=/opt/eslint/node_modules
ENTRYPOINT ["/opt/eslint/node_modules/.bin/eslint"]
