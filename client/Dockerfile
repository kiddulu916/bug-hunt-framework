FROM node:20-alpine
WORKDIR /app
COPY client/package.json client/package-lock.json ./
RUN npm ci
COPY client/ .
CMD ["npm", "run", "dev"]
