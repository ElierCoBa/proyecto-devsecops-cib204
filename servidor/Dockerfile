# ============================================================================
#   Dockerfile  -  Servicio de cifrado (Debian Slim Parcheado)
# ============================================================================

FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY *.js ./

FROM node:20-slim
WORKDIR /app

# 1. Actualizar paquetes del sistema operativo y parchear vulnerabilidades (SIENDO ROOT)
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Crear un usuario del sistema sin privilegios (Mitigación CWE-250)
RUN useradd --system --no-create-home appuser

# 3. Copiar únicamente los archivos necesarios desde la etapa de compilación
COPY --from=build /app /app
RUN chown -R appuser:appuser /app

# 4. Cambiar al usuario sin privilegios al final de todo
USER appuser

EXPOSE 3000
CMD ["node", "servidor.js"]