const mysql = require("mysql2/promise");
require("dotenv").config();

const pool = mysql.createPool({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
  port: process.env.PORT,
  waitForConnections: true,
  connectionLimit: 10,
});

pool
  .getConnection()
  .then((conn) => {
    console.log("Connecté à la base de données MySQL.");
    conn.release();
  })
  .catch((err) => {
    console.error("Erreur de connexion à la base de données:", err.message);
  });

module.exports = pool;
//test
