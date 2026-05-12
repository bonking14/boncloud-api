const pool = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// REGISTRO
const register = async (req, res) => {
  const { nombre, email, password } = req.body;

  try {
    // Verificar si el correo ya existe
    const existe = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
    if (existe.rows.length > 0) {
      return res.status(400).json({ error: 'Este correo ya está registrado.' });
    }

    // Validar contraseña segura
    const regex = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*]).{8,}$/;
    if (!regex.test(password)) {
      return res.status(400).json({
        error: 'La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un símbolo (!@#$%^&*).'
      });
    }

    // Encriptar contraseña
    const hash = await bcrypt.hash(password, 12);

    // Guardar usuario
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3) RETURNING id, nombre, email',
      [nombre, email, hash]
    );

    res.status(201).json({
      mensaje: 'Usuario registrado exitosamente.',
      usuario: result.rows[0]
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
};

// LOGIN
const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Buscar usuario
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciales incorrectas.' });
    }

    const usuario = result.rows[0];

    // Verificar si está bloqueado
    if (usuario.bloqueado) {
      return res.status(403).json({ error: 'Cuenta bloqueada. Contacta al administrador.' });
    }

    // Verificar contraseña
    const valida = await bcrypt.compare(password, usuario.password);

    if (!valida) {
      // Sumar intento fallido
      const intentos = usuario.intentos_fallidos + 1;
      const bloqueado = intentos >= 5;

      await pool.query(
        'UPDATE usuarios SET intentos_fallidos = $1, bloqueado = $2 WHERE id = $3',
        [intentos, bloqueado, usuario.id]
      );

      if (bloqueado) {
        return res.status(403).json({ error: 'Cuenta bloqueada por 5 intentos fallidos.' });
      }

      return res.status(401).json({
        error: `Credenciales incorrectas. Intentos fallidos: ${intentos}/5`
      });
    }

    // Resetear intentos fallidos
    await pool.query(
      'UPDATE usuarios SET intentos_fallidos = 0, ultimo_login = NOW() WHERE id = $1',
      [usuario.id]
    );

    // Generar token JWT
    const token = jwt.sign(
      { id: usuario.id, email: usuario.email, nombre: usuario.nombre },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN }
    );

    res.json({
      mensaje: 'Login exitoso.',
      token,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
};

module.exports = { register, login };