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
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();
    const result = await conn.query(
      "INSERT INTO users (email, motdepasse, nom, prenom, codepostal, ville) VALUES (?, ?, ?, ?, ?, ?)",
      [email, motdepasse, nom, prenom, codepostal, ville]
    );
    conn.release();

    // Convertir les BigInt en chaîne avant de les envoyer dans la réponse
    const resultStringify = JSON.parse(
      JSON.stringify(result, (key, value) =>
        typeof value === "bigint" ? value.toString() : value
      )
    );

    res
      .status(200)
      .json({
        message: "Utilisateur créé avec succès",
        result: resultStringify,
      });
  } catch (err) {
    console.error("Erreur lors de l'inscription:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

///////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////

app.listen(port, () => {
  console.log("Server started on port " + port);
});
