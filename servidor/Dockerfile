# ============================================================================
#   Dockerfile  -  Servicio de cifrado
#   >>> VERSION SEGURA (Multi-stage build & Usuario sin privilegios) <<<
# ============================================================================

# Etapa 1: Construcción y preparación de dependencias
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./

# Nota: Si tu proyecto no incluye package-lock.json, cambia 'npm ci' por 'npm install'
RUN npm ci --omit=dev

COPY *.js ./

# Etapa 2: Imagen final de producción ligera y segura
FROM node:20-slim
WORKDIR /app

# Crear un usuario del sistema sin privilegios (Mitigación CWE-250)
RUN useradd --system --no-create-home appuser

# Copiar únicamente los archivos necesarios desde la etapa de compilación
COPY --from=build /app /app
RUN chown -R appuser:appuser /app

# Cambiar al usuario sin privilegios
USER appuser

EXPOSE 3000
CMD ["node", "servidor.js"]