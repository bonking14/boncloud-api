const jwt = require('jsonwebtoken');
require('dotenv').config();

const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado. Token requerido.' });
  }

  try {
    const verificado = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = verificado;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido o expirado.' });
  }
};

module.exports = verificarToken;