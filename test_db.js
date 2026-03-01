const pool = require('./db');

(async () => {
  try {
    const res = await pool.query('SELECT NOW()');
    console.log('✅ Connessione riuscita! Ora:', res.rows[0]);
    pool.end();
  } catch (err) {
    console.error('❌ Errore di connessione:', err);
  }
})();
