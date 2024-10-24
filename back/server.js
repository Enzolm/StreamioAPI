const express = require("express");
const mariadb = require("mariadb");
const cors = require("cors");

const app = express();
const port = 3000;

app.use(cors());

app.get("/", (req, res) => {});

app.use(express.json());

//connexion à la BDD
require("dotenv").config();

const pool = mariadb.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: process.env.DB_CONNECTION_LIMIT,
});

//test de la connexion
pool
  .getConnection()
  .then((conn) => {
    console.log("Connected to database");
    conn.release();
  })
  .catch((err) => {
    console.error("Error connecting to database", err);
  });

app.post("/signup", async (req, res) => {
  console.log(req.body);
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;
  console.log(email);

  try {
    const conn = await pool.getConnection();
    const result = await conn.query(
      "INSERT INTO Users (email, motdepasse, nom, prenom, codepostal, ville) VALUES (?, ?, ?, ?, ?, ?)",
      [email, motdepasse, nom, prenom, codepostal, ville]
    );
    conn.release();
    throw new Error("Erreur");
    res.status(200).send(result);
  } catch (err) {
    res.status(500).send(err);
    console.error(err);
  }
});

app.listen(port, () => {
  console.log("Server started on port " + port);
});
