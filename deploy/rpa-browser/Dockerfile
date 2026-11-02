# M16-T1: the isolated headless browser service. The Playwright image
# carries the browser and its system libraries; its version matches the
# playwright package in package.json.
FROM mcr.microsoft.com/playwright:v1.49.0-jammy
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY steps.mjs server.mjs ./
USER pwuser
ENV PORT=8099
EXPOSE 8099
CMD ["node", "server.mjs"]
