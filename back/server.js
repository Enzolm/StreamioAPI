const express = require("express");
const mariadb = require("mariadb");
const cors = require("cors");
const bcrypt = require("bcrypt"); // Pour hasher le mot de passe
const jwt = require("jsonwebtoken"); // Pour générer le token JWT
require("dotenv").config();

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());

// Connexion à la BDD
const pool = mariadb.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  port: process.env.DB_PORT,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: process.env.DB_CONNECTION_LIMIT,
});

// Test de la connexion
pool
  .getConnection()
  .then((conn) => {
    console.log("Connected to database");
    conn.release();
  })
  .catch((err) => {
    console.error("Error connecting to database", err);
  });

// Route d'inscription
app.post("/signup", async (req, res) => {
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(motdepasse, 10);

    // Insérer l'utilisateur avec le mot de passe hashé
    const result = await conn.query(
      "INSERT INTO users (email, motdepasse, nom, prenom, codepostal, ville) VALUES (?, ?, ?, ?, ?, ?)",
      [email, hashedPassword, nom, prenom, codepostal, ville]
    );
    conn.release();

    // Générer un token JWT
    const token = jwt.sign(
      { email, nom, prenom }, // Payload
      process.env.JWT_SECRET, // Clé secrète
      { expiresIn: "1h" } // Expiration du token
    );

    res.status(200).json({
      message: "Utilisateur créé avec succès",
      token, // Envoyer le token au client
    });
  } catch (err) {
    console.error("Erreur lors de l'inscription:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

//login
app.post("/login", async (req, res) => {
  const { email, motdepasse } = req.body;

  if (!email || !motdepasse) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();

    // Récupérer l'utilisateur avec cet email
    const result = await conn.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (result.length === 0) {
      return res.status(404).send("Utilisateur non trouvé");
    }

    const user = result[0];

    // Vérifier le mot de passe
    const passwordMatch = await bcrypt.compare(motdepasse, user.motdepasse);

    if (!passwordMatch) {
      return res.status(401).send("Mot de passe incorrect");
    }

    // Générer un token JWT
    const token = jwt.sign(
      {
        email: user.email,
        nom: user.nom,
        prenom: user.prenom,
        isAdmin: user.admin,
      },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Connexion réussie",
      token,
    });
  } catch (err) {
    console.error("Erreur lors de la connexion:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.post("/verify-token", (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Récupérer le token après "Bearer"

  console.log("Token reçu :", token);

  if (!token) {
    return res.status(403).send("Un jeton est requis");
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send("Jeton invalide");
    }

    res.json({ message: "Ceci est une route protégée", user: decoded });
  });
});

//get user

app.get("/get/user", async (req, res) => {
  const email = "lemaireenzo91@gmail.com";

  if (!email) {
    return res.status(400).send("L'email est requis");
  }

  try {
    const conn = await pool.getConnection();

    // Récupérer l'utilisateur avec cet email
    const result = await conn.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (result.length === 0) {
      return res.status(404).send("Utilisateur non trouvé");
    }

    const user = result[0];

    res.status(200).json(user);
  } catch (err) {
    console.error("Erreur lors de la récupération de l'utilisateur:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

//update user
app.put("/update/user", async (req, res) => {
  console.log(req.body);
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();

    // Hasher le mot de passe
    const hashedPassword = await bcrypt.hash(motdepasse, 10);

    // Insérer l'utilisateur avec le mot de passe hashé
    const result = await conn.query(
      "UPDATE users SET email = ?, motdepasse = ?, nom = ?, prenom = ?, codepostal = ?, ville = ? WHERE email = 'lemaireenzo91@gmail.com'",
      [email, hashedPassword, nom, prenom, codepostal, ville]
    );
    conn.release();

    // Générer un token JWT
    const token = jwt.sign(
      { email, nom, prenom }, // Payload
      process.env.JWT_SECRET, // Clé secrète
      { expiresIn: "1h" } // Expiration du token
    );

    res.status(200).json({
      message: "Utilisateur modifié avec succès",
      token, // Envoyer le token au client
    });
  } catch (err) {
    console.error("Erreur lors de la modification:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.delete("/delete/user", async (req, res) => {
  const email = "lemaireenzo91@gmail.com";

  if (!email) {
    return res.status(400).send("L'email est requis");
  }

  try {
    const conn = await pool.getConnection();

    // Récupérer l'utilisateur avec cet email
    const result = await conn.query("DELETE FROM users WHERE email = ?", [
      email,
    ]);

    if (result.length === 0) {
      return res.status(404).send("Utilisateur non trouvé");
    }

    res.status(200).json({ message: "Utilisateur supprimé" });
  } catch (err) {
    console.error("Erreur lors de la suppression de l'utilisateur:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.post("/create/service", async (req, res) => {
  const { service_titre, service_description, categorie } = req.body;

  try {
    const conn = await pool.getConnection();

    // Insérer le service
    const result = await conn.query(
      "INSERT INTO service (Nom, description, Photo) VALUES (?, ?, ?)",
      [service_titre, service_description, categorie]
    );
    conn.release();

    res.status(200).json({
      message: "Service créé avec succès",
    });
  } catch (err) {
    console.error("Erreur lors de la création du service:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.post("/create/service", async (req, res) => {
  const { service_titre, service_description, service_categorie } = req.body;

  if (!service_titre || !service_description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();

    const result = await conn.query(
      "INSERT INTO service (Nom, description, Photo) VALUES (?, ?, ?)",
      [service_titre, service_description, service_categorie]
    );
    conn.release();

    res.status(200).json({
      message: "Service créé avec succès",
    });
  } catch (err) {
    console.error("Erreur lors de la création du service:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.get("/get/services", async (req, res) => {
  const { orderBy } = req.query;

  try {
    const conn = await pool.getConnection();

    let query = "SELECT * FROM service";

    if (orderBy) {
      query += ` ORDER BY ${orderBy}`;
    }

    const result = await conn.query(query);

    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des services:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.delete("/delete/service/:id", async (req, res) => {
  const { id } = req.params;
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(403).send("Un jeton est requis");
  }

  jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(401).send("Jeton invalide");
    }

    if (!decoded.isAdmin) {
      return res
        .status(403)
        .send("Accès interdit, vous devez être administrateur");
    }

    try {
      const conn = await pool.getConnection();
      const result = await conn.query("DELETE FROM service WHERE id = ?", [id]);
      conn.release();

      if (result.affectedRows === 0) {
        return res.status(404).send("Service non trouvé");
      }

      res.status(200).json({ message: "Service supprimé avec succès" });
    } catch (err) {
      console.error("Erreur lors de la suppression du service:", err);
      res.status(500).send("Erreur interne du serveur");
    }
  });
});

// Lancement du serveur
app.listen(port, () => {
  console.log("Server started on port " + port);
});
