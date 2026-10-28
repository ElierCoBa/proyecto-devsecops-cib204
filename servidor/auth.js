// ============================================================================
//   auth.js  -  Gestion de identidad y acceso (IAM)
//   >>> VERSION SEGURA (Validación JWKS / RS256) <<<
// ============================================================================

const { expressjwt } = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const config = require('./config');

// Configuración del middleware de validación contra el JWKS de Keycloak
const checkJwt = expressjwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: config.JWKS_URI || `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}/protocol/openid-connect/certs`
  }),
  issuer: config.KEYCLOAK_ISSUER || `${config.KEYCLOAK_URL}/realms/${config.KEYCLOAK_REALM}`,
  algorithms: ['RS256']
});

function requiereAuth(req, res, next) {
  // Si el control de acceso está apagado, deja pasar (útil para entornos de pruebas locales específicos)
  if (!config.AUTH_ENABLED) {
    return next();
  }

  // Ejecuta la validación del token JWT mediante JWKS
  checkJwt(req, res, (err) => {
    if (err) {
      return res.status(401).json({ error: 'No autorizado o token inválido' });
    }
    return next();
  });
}

module.exports = { requiereAuth };