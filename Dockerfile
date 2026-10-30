# Base do Playwright DEVE casar com a versão travada no package-lock (1.59.1).
FROM mcr.microsoft.com/playwright:v1.59.1-noble
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json ./
COPY src ./src
RUN npm run build
RUN npm prune --omit=dev
# garante o Chromium que casa exatamente com o playwright instalado (self-heal se o lock mudar)
RUN npx playwright install chromium
ENV NODE_ENV=production
EXPOSE 3000
CMD ["node", "build/http-server.js"]
