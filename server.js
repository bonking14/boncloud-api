const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const authRoutes = require('./routes/auth');

const app = express();

app.use(helmet());

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://127.0.0.1:5500',
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { error: 'Demasiados intentos. Espera 15 minutos.' }
});
app.use('/api/auth', limiter);

app.use(express.json());
app.use('/api/auth', authRoutes);

app.get('/', (req, res) => {
  res.json({ mensaje: 'BonCloud API corriendo' });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en puerto ${PORT}`);
});