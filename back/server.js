const express = require("express");
const mariadb = require("mariadb");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
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
  connectionLimit: process.env.DB_CONNECTION_LIMIT || 5, // Valeur par défaut
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

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(403).send("Un jeton est requis");

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(401).send("Jeton invalide");
    req.user = user;
    next();
  });
};

// Route d'inscription
app.post("/signup", async (req, res) => {
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();
    const hashedPassword = await bcrypt.hash(motdepasse, 10);

    await conn.query("INSERT INTO users (email, motdepasse, nom, prenom, codepostal, ville) VALUES (?, ?, ?, ?, ?, ?)", [email, hashedPassword, nom, prenom, codepostal, ville]);
    conn.release();

    const token = jwt.sign({ email, nom, prenom }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ message: "Utilisateur créé avec succès", token });
  } catch (err) {
    console.error("Erreur lors de l'inscription:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.post("/verify-token", authenticateToken, async (req, res) => {
  try {
    const user = req.user; // L'utilisateur est ajouté par le middleware authenticateToken
    res.status(200).json({ isAdmin: user.isAdmin });
  } catch (err) {
    console.error("Erreur lors de la vérification du token:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

// Route de connexion
app.post("/login", async (req, res) => {
  const { email, motdepasse } = req.body;

  if (!email || !motdepasse) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM users WHERE email = ?", [email]);

    if (result.length === 0) return res.status(404).send("Utilisateur non trouvé");

    const user = result[0];
    const passwordMatch = await bcrypt.compare(motdepasse, user.motdepasse);

    if (!passwordMatch) return res.status(401).send("Mot de passe incorrect");

    const token = jwt.sign({ email: user.email, nom: user.nom, prenom: user.prenom, isAdmin: user.admin }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ message: "Connexion réussie", token });
  } catch (err) {
    console.error("Erreur lors de la connexion:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

// Mise à jour utilisateur
app.put("/update/user", authenticateToken, async (req, res) => {
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();
    const hashedPassword = await bcrypt.hash(motdepasse, 10);

    const result = await conn.query("UPDATE users SET motdepasse = ?, nom = ?, prenom = ?, codepostal = ?, ville = ? WHERE email = ?", [hashedPassword, nom, prenom, codepostal, ville, email]);
    conn.release();

    if (result.affectedRows === 0) return res.status(404).send("Utilisateur non trouvé");

    res.status(200).json({ message: "Utilisateur mis à jour avec succès" });
  } catch (err) {
    console.error("Erreur lors de la mise à jour:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

// Création de service
app.post("/create/service", async (req, res) => {
  const { service_titre, service_description, categorie } = req.body;

  if (!service_titre || !service_description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();
    await conn.query("INSERT INTO service (Nom, description, Photo) VALUES (?, ?, ?)", [service_titre, service_description, categorie]);
    conn.release();

    res.status(201).json({ message: "Service créé avec succès" });
  } catch (err) {
    console.error("Erreur lors de la création du service:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

// Suppression d'un service (admin)
app.delete("/delete/service/:id", authenticateToken, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).send("Accès interdit");

  try {
    const conn = await pool.getConnection();
    const result = await conn.query("DELETE FROM service WHERE id = ?", [req.params.id]);
    conn.release();

    if (result.affectedRows === 0) return res.status(404).send("Service non trouvé");

    res.status(200).json({ message: "Service supprimé avec succès" });
  } catch (err) {
    console.error("Erreur lors de la suppression du service:", err);
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

app.post("/create/service", authenticateToken, async (req, res) => {
  const { Nom, categorie, description, Prix, Photo, Video } = req.body;

  if (!Nom || !categorie || !description) {
    return res.status(400).json({ message: "Tous les champs obligatoires doivent être remplis" });
  }

  try {
    const conn = await pool.getConnection();
    const sql = "INSERT INTO service (Nom, categorie, description, Prix, Photo, Video) VALUES (?, ?, ?, ?, ?, ?)";
    await conn.query(sql, [Nom, categorie, description, Prix, Photo, Video]);
    conn.release();

    res.status(201).json({ message: "Service ajouté avec succès" });
  } catch (error) {
    console.error("Erreur lors de l'ajout du service:", error);
    res.status(400).json({ message: "Erreur lors de l'ajout du service" });
  }
});

app.put("/update/service/:id", authenticateToken, async (req, res) => {
  const { service_titre, service_description, categorie, photo } = req.body;
  const serviceId = req.params.id;

  // Vérifiez si tous les champs nécessaires sont présents
  if (!service_titre || !service_description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }

  try {
    const conn = await pool.getConnection();

    // Si vous voulez mettre à jour Photo, vous devez ajouter ce paramètre dans la requête SQL
    const result = await conn.query("UPDATE service SET Nom = ?, description = ?, categorie = ?, Photo = ? WHERE Id_service = ?", [service_titre, service_description, categorie, photo || "", serviceId]);
    conn.release();

    // Vérifiez si des lignes ont été affectées
    if (result.affectedRows === 0) {
      return res.status(404).send("Service non trouvé");
    }

    res.status(200).json({ message: "Service mis à jour avec succès" });
  } catch (err) {
    console.error("Erreur lors de la mise à jour du service:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.get("/taches/active", async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const result = await conn.query('SELECT * FROM todo WHERE statut = "en cours"');
    conn.release();
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des commandes en cours:", err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

app.get("/taches/terminer", async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const result = await conn.query('SELECT * FROM todo WHERE statut = "terminer"');
    conn.release();
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des commandes terminées:", err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

app.get("/taches/search", async (req, res) => {
  const searchTerm = req.query.searchTerm || "";
  try {
    const conn = await pool.getConnection();
    const query = `SELECT * FROM todo WHERE titre LIKE ? OR statut LIKE ?`;
    const result = await conn.query(query, [`%${searchTerm}%`, `%${searchTerm}%`]);
    conn.release();
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la recherche des commandes:", err);
    res.status(500).json({ message: "Erreur serveur" });
  }
});

app.get("/get/users", async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM users");
    conn.release();
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des utilisateurs:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.post("/create/users", async (req, res) => {
  const { email, nom, prenom } = req.body;
  console.log(req.body, email, nom, prenom);
  const adminCreation = 1;
  if (!email || !nom || !prenom) {
    return res.status(400).send("Tous les champs sont requis", adminCreation, email, nom, prenom);
  }

  try {
    const conn = await pool.getConnection();

    await conn.query("INSERT INTO users (email, nom, prenom, admin_creation) VALUES (?, ?, ?, ?)", [email, nom, prenom, adminCreation]);
    conn.release();

    // const token = jwt.sign({ email, nom, prenom }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ message: "Utilisateur créé avec succès" });
  } catch (err) {
    console.error("Erreur lors de l'inscription:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.delete("/delete/user/:id", async (req, res) => {
  try {
    const conn = await pool.getConnection();
    const result = await conn.query("DELETE FROM users WHERE id = ?", [req.params.id]);
    conn.release();

    if (result.affectedRows === 0) return res.status(404).send("Utilisateur non trouvé");

    res.status(200).json({ message: "Utilisateur supprimé avec succès" });
  } catch (err) {
    console.error("Erreur lors de la suppression de l'utilisateur:", err);
    res.status(500).send("Erreur interne du serveur");
  }
});

app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
