FROM node:20-alpine AS builder

WORKDIR /app

# Instalar as dependências necessárias para o Prisma
RUN apk add --no-cache openssl libc6-compat

COPY package*.json ./
RUN npm install

# Copiar apenas o schema do Prisma primeiro para gerar os tipos
COPY prisma ./prisma
RUN npx prisma generate

# Agora copiar o resto do código
COPY . .

RUN npm run build

FROM node:20-alpine

WORKDIR /app

# Instalar as dependências necessárias no contêiner final
RUN apk add --no-cache openssl libc6-compat

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY package*.json ./
COPY .env ./

# Gerar o cliente Prisma novamente no contêiner final
RUN npx prisma generate

CMD ["node", "dist/main.js"]