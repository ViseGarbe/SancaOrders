// db.js
// -- ALTER USER postgres WITH PASSWORD 'Sanca2025!';

const { Pool } = require('pg');

const pool = new Pool({
  user: 'postgres',           // utente PostgreSQL
  host: 'localhost',        // stai lavorando in locale
  database: 'SancaOrders',  // nome del DB creato
  password: 'Sanca2025!',   // la password che hai scelto
  port: 5500,                 // porta standard
});

module.exports = pool;