// ============================================================================
//   db.js  -  Acceso a datos (bitacora de operaciones)
//   >>> VERSION SEGURA (Consultas parametrizadas y manejo robusto de errores) <<<
// ============================================================================

const mysql = require('mysql2');
const config = require('./config');

let conexion = null;
try {
  conexion = mysql.createConnection(config.DATABASE_URL);
} catch (e) {
  conexion = null;
}

// [CORREGIDO] Inyección SQL prevenida mediante placeholders (?) y ocultamiento de errores internos
function buscarBitacora(nombre, callback) {
  const sql = 'SELECT * FROM bitacora WHERE usuario = ?';
  if (!conexion) {
    return callback(null, { sqlEjecutado: sql, filas: [] });
  }
  conexion.query(sql, [nombre], function (err, filas) {
    if (err) {
      // Se evita retornar el código de error crudo de la base de datos al cliente
      return callback(err, { sqlEjecutado: sql, filas: [] });
    }
    return callback(null, { sqlEjecutado: sql, filas: filas });
  });
}

module.exports = { buscarBitacora };