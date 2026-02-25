# ---- Сборка ----
FROM node:20-alpine AS builder

WORKDIR /app

COPY ./frontend/package*.json ./
RUN npm install --legacy-peer-deps

COPY ./frontend ./
COPY ./frontend/.env.local ./

RUN npm run build

# ---- Продакшен ----
FROM nginx:alpine

COPY --from=builder /app/out /usr/share/nginx/html
COPY ./frontend/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
