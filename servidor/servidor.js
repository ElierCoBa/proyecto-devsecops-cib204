// ============================================================================
//  servidor.js  -  API REST del servicio de cifrado
//  CIB-204 Seguridad del Software - Universidad Cenfotec
//  >>> VERSION SEGURA (Laboratorio DevSecOps) <<<
// ============================================================================

const express = require('express');
const cors = require('cors');
const { exec, execFile } = require('child_process');
const cifrado = require('./cifrado');
const db = require('./db');
const config = require('./config');
const { requiereAuth } = require('./auth');

const app = express();
app.use(express.json());

app.use(cors());

// El servicio genera su par de llaves al arrancar.
const llaves = cifrado.generarLlaves();

app.get('/salud', (req, res) => {
  res.json({ estado: 'ok', version: 'seguro-1.0' });
});

app.get('/llave', (req, res) => {
  res.json({ llavePublica: llaves.publicKey });
});

app.post('/cifrar', requiereAuth, (req, res) => {
  try {
    const texto = req.body.texto;
    const resultado = cifrado.cifrar(texto, llaves.publicKey);
    res.json({ cifrado: resultado });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/descifrar', requiereAuth, (req, res) => {
  try {
    const cifradoTxt = req.body.cifrado;
    const resultado = cifrado.descifrar(cifradoTxt, llaves.privateKey);
    res.json({ descifrado: resultado });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Consulta a la bitacora usando consulta parametrizada (SQLi corregido)
app.get('/buscar', (req, res) => {
  const nombre = req.query.nombre || '';
  db.buscarBitacora(nombre, (err, data) => {
    res.json(data);
  });
});

// [CORREGIDO] Eliminado eval(), reemplazado por suma segura de números
app.post('/calcular', (req, res) => {
  const nums = Array.isArray(req.body.numeros) ? req.body.numeros : [];
  if (!nums.every(n => typeof n === 'number')) {
    return res.status(400).json({ error: 'Entrada invalida' });
  }
  res.json({ resultado: nums.reduce((a, b) => a + b, 0) });
});

// [CORREGIDO] Uso de execFile y validación estricta del parámetro host con regex
app.get('/diagnostico', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  if (!/^[a-zA-Z0-9.-]{1,64}$/.test(host)) {
    return res.status(400).json({ error: 'Host invalido' });
  }
  execFile('ping', ['-c', '1', host], (err, stdout, stderr) => {
    res.json({ salida: stdout, error: stderr });
  });
});

if (require.main === module) {
  app.listen(config.PUERTO, () => {
    console.log('Servicio de cifrado escuchando en el puerto ' + config.PUERTO);
    console.log('AUTH_ENABLED =', config.AUTH_ENABLED);
  });
}

module.exports = app;