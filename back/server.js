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
});

// Test de la connexion
pool
  .getConnection()
  .then((conn) => {
    console.log("Connected to database");
    if (conn) conn.release();
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
    console.log("Utilisateur authentifié:", user);
    next();
  });
};

// Route d'inscription
app.post("/signup", async (req, res) => {
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    const conn = await pool.getConnection();
    const hashedPassword = await bcrypt.hash(motdepasse, 10);

    await conn.query("INSERT INTO users (email, motdepasse, nom, prenom, codepostal, ville) VALUES (?, ?, ?, ?, ?, ?)", [email, hashedPassword, nom, prenom, codepostal, ville]);

    const token = jwt.sign({ email, nom, prenom }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ message: "Utilisateur créé avec succès", token });
  } catch (err) {
    console.error("Erreur lors de l'inscription:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
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
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM users WHERE email = ?", [email]);

    if (result.length === 0) return res.status(404).send("Utilisateur non trouvé");

    const user = result[0];
    const passwordMatch = await bcrypt.compare(motdepasse, user.motdepasse);

    if (!passwordMatch) return res.status(401).send("Mot de passe incorrect");

    console.log("Utilisateur connecté:", user.isEmployee);
    const token = jwt.sign({ email: user.email, nom: user.nom, prenom: user.prenom, isAdmin: user.admin, isEmployee: user.isEmployee }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ message: "Connexion réussie", token });
  } catch (err) {
    console.error("Erreur lors de la connexion:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

// Mise à jour utilisateur
app.put("/update/user", authenticateToken, async (req, res) => {
  const { email, motdepasse, nom, prenom, codepostal, ville } = req.body;

  if (!email || !motdepasse || !nom || !prenom || !codepostal || !ville) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();
    const hashedPassword = await bcrypt.hash(motdepasse, 10);

    const result = await conn.query("UPDATE users SET motdepasse = ?, nom = ?, prenom = ?, codepostal = ?, ville = ? WHERE email = ?", [hashedPassword, nom, prenom, codepostal, ville, email]);

    if (result.affectedRows === 0) return res.status(404).send("Utilisateur non trouvé");

    res.status(200).json({ message: "Utilisateur mis à jour avec succès" });
  } catch (err) {
    console.error("Erreur lors de la mise à jour:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

// Création de service
app.post("/create/service", async (req, res) => {
  const { service_titre, service_description, categorie } = req.body;

  if (!service_titre || !service_description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.query("INSERT INTO service (Nom, description, Photo) VALUES (?, ?, ?)", [service_titre, service_description, categorie]);

    res.status(201).json({ message: "Service créé avec succès" });
  } catch (err) {
    console.error("Erreur lors de la création du service:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

// Suppression d'un service (admin)
app.delete("/delete/service/:id", authenticateToken, async (req, res) => {
  if (!req.user.isAdmin) return res.status(403).send("Accès interdit");

  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("DELETE FROM service WHERE id = ?", [req.params.id]);

    if (result.affectedRows === 0) return res.status(404).send("Service non trouvé");

    res.status(200).json({ message: "Service supprimé avec succès" });
  } catch (err) {
    console.error("Erreur lors de la suppression du service:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

app.get("/get/services", async (req, res) => {
  const { orderBy } = req.query;

  let conn;
  try {
    conn = await pool.getConnection();

    let query = "SELECT * FROM service";

    if (orderBy) {
      console.log("Order by:", orderBy);
      query += ` ORDER BY ${orderBy}`;
    }

    const result = await conn.query(query);

    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des services:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

app.post("/create/service", authenticateToken, async (req, res) => {
  const { Nom, categorie, description, Prix, Photo, Video } = req.body;

  if (!Nom || !categorie || !description) {
    return res.status(400).json({ message: "Tous les champs obligatoires doivent être remplis" });
  }
  let conn;
  try {
    conn = await pool.getConnection();
    const sql = "INSERT INTO service (Nom, categorie, description, Prix, Photo, Video) VALUES (?, ?, ?, ?, ?, ?)";
    await conn.query(sql, [Nom, categorie, description, Prix, Photo, Video]);

    res.status(201).json({ message: "Service ajouté avec succès" });
  } catch (error) {
    console.error("Erreur lors de l'ajout du service:", error);
    res.status(400).json({ message: "Erreur lors de l'ajout du service" });
  } finally {
    if (conn) conn.release();
  }
});

app.put("/update/service/:id", authenticateToken, async (req, res) => {
  const { service_titre, service_description, categorie, photo } = req.body;
  const serviceId = req.params.id;

  // Vérifiez si tous les champs nécessaires sont présents
  if (!service_titre || !service_description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();

    // Si vous voulez mettre à jour Photo, vous devez ajouter ce paramètre dans la requête SQL
    const result = await conn.query("UPDATE service SET Nom = ?, description = ?, categorie = ?, Photo = ? WHERE Id_service = ?", [service_titre, service_description, categorie, photo || "", serviceId]);

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
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query('SELECT * FROM todo WHERE statut = "en cours"');
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des commandes en cours:", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/taches/terminer", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query('SELECT * FROM todo WHERE statut = "terminer"');
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des commandes terminées:", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/taches/search", async (req, res) => {
  const searchTerm = req.query.searchTerm || "";
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `SELECT * FROM todo WHERE titre LIKE ? OR statut LIKE ?`;
    const result = await conn.query(query, [`%${searchTerm}%`, `%${searchTerm}%`]);
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la recherche des commandes:", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/get/users", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM users");
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des utilisateurs:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

app.post("/create/users", async (req, res) => {
  const { email, nom, prenom } = req.body;
  console.log(req.body, email, nom, prenom);
  const adminCreation = 1;
  if (!email || !nom || !prenom) {
    return res.status(400).send("Tous les champs sont requis", adminCreation, email, nom, prenom);
  }
  let conn;
  try {
    conn = await pool.getConnection();

    await conn.query("INSERT INTO users (email, nom, prenom, admin_creation) VALUES (?, ?, ?, ?)", [email, nom, prenom, adminCreation]);

    // const token = jwt.sign({ email, nom, prenom }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ message: "Utilisateur créé avec succès" });
  } catch (err) {
    console.error("Erreur lors de l'inscription:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

app.delete("/delete/user/:id", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("DELETE FROM users WHERE id = ?", [req.params.id]);

    if (result.affectedRows === 0) return res.status(404).send("Utilisateur non trouvé");

    res.status(200).json({ message: "Utilisateur supprimé avec succès" });
  } catch (err) {
    console.error("Erreur lors de la suppression de l'utilisateur:", err);
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});
app.get("/taches/search", authenticateToken, async (req, res) => {
  const searchTerm = req.query.searchTerm || "";
  const order = req.query.order || "ASC";
  let conn;
  try {
    conn = await pool.getConnection();
    const query = `
      SELECT * FROM todo
      WHERE titre LIKE ? OR statut LIKE ?
      ORDER BY titre ${order === "DESC" ? "DESC" : "ASC"}
    `;
    const result = await conn.query(query, [`%${searchTerm}%`, `%${searchTerm}%`]);
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la recherche des commandes:", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.delete("/delete/taches/:id", async (req, res) => {
  const { id } = req.params; // Récupère l'ID de la commande passé dans l'URL

  let conn;
  try {
    conn = await pool.getConnection();

    // Effectuer la suppression dans la base de données en utilisant l'ID
    const result = await conn.query("DELETE FROM todo WHERE id = ?", [id]);

    if (result.affectedRows === 0) {
      return res.status(404).send("Commande non trouvée"); // Si aucune ligne n'a été affectée, la commande n'existe pas
    }

    res.status(200).json({ message: "Commande supprimée avec succès" }); // Si la commande a été supprimée
  } catch (err) {
    console.error("Erreur lors de la suppression de la commande:", err);
    res.status(500).send("Erreur interne du serveur"); // Gérer les erreurs du serveur
  } finally {
    if (conn) conn.release(); // Libérer la connexion à la base de données
  }
});

app.get("/get/employee", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM users WHERE isEmployee = 1");
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération des employés : ", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
