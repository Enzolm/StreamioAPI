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
    const token = jwt.sign({ id: user.id, email: user.email, nom: user.nom, prenom: user.prenom, isAdmin: user.admin, isEmployee: user.isEmployee }, process.env.JWT_SECRET, { expiresIn: "1h" });
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

app.put("/update/user/:id", async (req, res) => {
  const { email, nom, prenom, isAdmin, isEmployee } = req.body;
  const userId = req.params.id;

  if (!email || !nom || !prenom || typeof isAdmin === "undefined" || typeof isEmployee === "undefined") {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();

    const result = await conn.query("UPDATE users SET email = ?, nom = ?, prenom = ?, admin = ?, isEmployee = ? WHERE id = ?", [email, nom, prenom, isAdmin, isEmployee, userId]);

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
  const { Nom, categorie, description } = req.body;
  console.log("Création de service avec les données:", req.body);
  if (!Nom || !description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.query("INSERT INTO service (Nom, description, categorie, Photo) VALUES (?, ?, ?, ?)", [Nom, description, categorie, "null"]);

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
  console.log("Suppression du service avec ID:", req.params.id, req.user);
  if (!req.user.isAdmin) return res.status(403).send("Accès interdit");

  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("DELETE FROM service WHERE Id_service = ?", [req.params.id]);

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

app.put("/update/service/:id", async (req, res) => {
  const { Nom, description, categorie } = req.body;
  const serviceId = req.params.id;
  console.log("Mise à jour du service avec ID:", serviceId, "avec les données:", req.body);

  // Vérifiez si tous les champs nécessaires sont présents
  if (!Nom || !description || !categorie) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();

    // Si vous voulez mettre à jour Photo, vous devez ajouter ce paramètre dans la requête SQL
    const result = await conn.query("UPDATE service SET Nom = ?, description = ?, categorie = ? WHERE Id_service = ?", [Nom, description, categorie, serviceId]);

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
  const idDelete = req.params.id;
  console.log("Suppression de l'utilisateur avec ID:", idDelete);
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.query("DELETE FROM todo WHERE attribue_id = ?", [idDelete]);
    const result = await conn.query("DELETE FROM users WHERE id = ?", [idDelete]);

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

app.get("/get/favoris", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Token manquant" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const id_user = decoded.id;

    console.log("ID utilisateur récupéré du token :", id_user);

    if (!id_user) {
      return res.status(400).json({ error: "ID utilisateur manquant dans le token" });
    }

    let conn;
    try {
      conn = await pool.getConnection();
      // const result = await conn.query("SELECT * FROM favoris WHERE id_user = ?", [id_user]);
      const result = await conn.query("SELECT f.*, service.*  FROM favoris f INNER JOIN service ON f.id_service = service.Id_service WHERE f.id_user = ?", [id_user]);
      res.status(200).json(result);
      console.log("Favoris récupérés pour l'utilisateur ID :", result);
    } finally {
      if (conn) conn.release();
    }
  } catch (err) {
    console.error("Erreur lors de la récupération des favoris : ", err);
    return res.status(401).json({ error: "Jeton invalide ou expiré" });
  }
});

app.get("/get/Onefavoris", async (req, res) => {
  const { id_user, id_service } = req.body;

  if (!id_user || !id_service) {
    return res.status(400).send("Tous les champs sont requis");
  }
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM favoris WHERE id_user = ? AND id_service = ?", [id_user, id_service]);
    if (result.length === 0) {
      return res.status(404).send("Aucun favori trouvé");
    }
    res.status(200).json(result);
  } catch (err) {
    console.error("Erreur lors de la récupération du favori : ", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.post("/create/favoris", async (req, res) => {
  const { id_service } = req.body;

  if (!id_service) {
    return res.status(400).json({ error: "id_service est requis" });
  }

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Token manquant" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const id_user = decoded.id;

    if (!id_user) {
      return res.status(400).json({ error: "ID utilisateur manquant dans le token" });
    }

    const conn = await pool.getConnection();
    try {
      await conn.query("INSERT INTO favoris (id_user, id_service) VALUES (?, ?)", [id_user, id_service]);
      res.status(201).json({ message: "Favori créé avec succès" });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur lors de la création du favori :", err);
    return res.status(401).json({ error: "Jeton invalide ou expiré" });
  }
});

app.delete("/delete/favoris/:id", async (req, res) => {
  const { id } = req.params;

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.query("DELETE FROM favoris WHERE id = ?", [id]);
    res.status(200).json({ message: "Favori supprimé avec succès" });
  } catch (err) {
    res.status(500).send("Erreur interne du serveur");
  } finally {
    if (conn) conn.release();
  }
});

// FLUTTER
const validStatuses = ["en cours", "fait", "annule"]; // Liste des statuts valides

app.put("/commande/attribue/:id", authenticateToken, async (req, res) => {
  const taskId = parseInt(req.params.id);
  const { attribue_id } = req.body;

  if (!attribue_id) {
    return res.status(400).json({ message: "ID de l'utilisateur requis" });
  }

  let conn;
  try {
    conn = await pool.getConnection();

    const result = await conn.query("UPDATE todo SET attribue_id = ? WHERE id = ?", [attribue_id, taskId]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Tâche non trouvée" });
    }

    // ✅ On convertit en Number pour éviter l'erreur de BigInt
    res.status(200).json({
      message: "Attribution réussie",
      taskId: Number(taskId),
      attribueId: Number(attribue_id),
    });
  } catch (err) {
    console.error("Erreur lors de la mise à jour de l'attribution de la tâche:", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/mestaches/search", authenticateToken, async (req, res) => {
  const order = req.query.order === "DESC" ? "DESC" : "ASC"; // Paramètre de tri
  let conn;

  try {
    const userId = req.user.id; // Récupération de l'ID utilisateur depuis le JWT
    console.log("User ID from JWT:", userId); // Affichez l'ID de l'utilisateur pour vérifier

    // Si l'ID n'est pas trouvé ou est invalide
    if (!userId) {
      return res.status(401).json({ message: "Utilisateur non authentifié" });
    }

    conn = await pool.getConnection();

    // Requête SQL pour récupérer toutes les tâches attribuées à l'utilisateur
    const query = `
      SELECT * FROM todo 
      WHERE attribue_id = ? 
      ORDER BY titre ${order}
    `;

    // Exécution de la requête avec l'ID utilisateur
    const result = await conn.query(query, [userId]);

    if (result.length > 0) {
      res.status(200).json(result); // Si des tâches sont trouvées
    } else {
      res.status(404).json({ message: "Aucune tâche trouvée" }); // Si aucune tâche n'est trouvée
    }
  } catch (err) {
    console.error("Erreur lors de la recherche des commandes attribuées:", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release(); // Libération de la connexion
  }
});

app.put("/taches/:id/status", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { statut } = req.body;

  // Vérification que le statut est valide
  if (!validStatuses.includes(statut)) {
    return res.status(400).json({ message: "Statut invalide" });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const query = "UPDATE todo SET statut = ? WHERE id = ?";
    const result = await conn.query(query, [statut, id]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Tâche non trouvée" });
    }

    res.status(200).json({ message: "Statut de la tâche mis à jour avec succès" });
  } catch (err) {
    console.error("Erreur lors de la mise à jour du statut :", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

//devis
app.get("/get/devis", async (req, res) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Token manquant" });
  }

  let conn;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const id_user = decoded.id;
    conn = await pool.getConnection();
    const rows = await conn.query("SELECT * FROM new_devis WHERE user_id = ?", [id_user]);
    res.status(200).json(rows);
  } catch (err) {
    console.error("Erreur lors de la récupération des devis :", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/get/all/devis", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT * FROM new_devis");

    // Ajoutez ce log pour voir la structure complète du résultat
    console.log("Structure du résultat :", result);

    res.status(200);
    res.json(result); // Changez ici : utilisez result au lieu de result.rows
    console.log("Récupération de tous les devis :", result);
  } catch (err) {
    console.error("Erreur lors de la récupération des devis :", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.post("/create/devis", async (req, res) => {
  console.log("Création de devis avec les données :", req.body);
  const { user_id, numero_devis, client, dateDevis, validiteDevis, sous_total, tauxTVA, montantTVA, montant_total, statut, conditions, commentaires, pdf_url, tache_list } = req.body;
  const { nom, telephone, adresse, ville } = client || {};

  if (!client || !numero_devis || !validiteDevis || !dateDevis || !tauxTVA) {
    return res.status(400).json({ error: "Champs obligatoires manquants" });
  }

  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Token manquant" });
  }

  console.log(tache_list);
  try {
    const conn = await pool.getConnection();
    try {
      const result = await conn.query(
        `INSERT INTO new_devis (
          user_id, numero_devis, client_nom, client_telephone, client_adresse, client_ville,
          date_devis, validite_devis, sous_total, taux_tva, montant_tva, montant_total,
          statut, conditions, commentaire, pdf_url, tache_list
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [user_id, numero_devis, nom, telephone, adresse, ville, dateDevis, validiteDevis, sous_total, tauxTVA, montantTVA, montant_total, statut, conditions, commentaires, pdf_url, JSON.stringify(tache_list)]
      );

      res.status(201).json({ message: "Devis créé avec succès" });
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur lors de la création du devis :", err);
    res.status(401).json({ error: "Jeton invalide ou expiré" });
  }
});

app.put("/update/devis/statut/:id", async (req, res) => {
  console.log("Mise à jour du devis :", req.body);
  const { id } = req.params;
  const { statut } = req.body;

  if (!id || !statut) {
    return res.status(400).json({ error: "Champs obligatoires manquants" });
  }
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query(
      `UPDATE new_devis SET
        statut = ? WHERE id = ?`,
      [statut, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Devis non trouvé" });
    }

    res.status(200).json({ message: "Devis mis à jour avec succès" });
  } catch (err) {
    console.error("Erreur lors de la mise à jour du devis :", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

// const decoded = jwt.verify("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NjIsImVtYWlsIjoiYW50b25pbkBnbWFpbC5jb20iLCJub20iOiJMZW1haXJlIiwicHJlbm9tIjoiRW56byIsImlzQWRtaW4iOjEsImlzRW1wbG95ZWUiOjAsImlhdCI6MTc0NzkxOTM2MCwiZXhwIjoxNzQ3OTIyOTYwfQ.fa6izCZEH-ny5usOhKWF6x4EbS9My-qp8Sn9COfwlTw", process.env.JWT_SECRET);
// console.log("Décodé:", decoded);

app.get("/get/count/todo", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT COUNT(*) AS count FROM todo WHERE attribue_id IS NOT NULL;");
    res.status(200).json({ count: Number(result[0].count) });
  } catch (err) {
    console.error("Erreur lors de la récupération du nombre de tâches :", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/get/all/employee/statut/todo", async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("SELECT u.id, u.nom,  COUNT(CASE WHEN t.statut = 'en cours' THEN 1 END) AS nb_en_cours, COUNT(CASE WHEN t.statut = 'fait' THEN 1 END) AS nb_fait FROM users u LEFT JOIN todo t ON t.attribue_id = u.id WHERE u.isEmployee = 1 GROUP BY u.id, u.nom;");

    const formattedResult = result.map((row) => ({
      id: Number(row.id),
      nom: row.nom,
      nb_en_cours: Number(row.nb_en_cours),
      nb_fait: Number(row.nb_fait),
    }));

    res.status(200).json(formattedResult);
  } catch (err) {
    console.error("Erreur lors de la récupération des employés et de leurs tâches :", err);
    res.status(500).json({ message: "Erreur serveur" });
  } finally {
    if (conn) conn.release();
  }
});

app.listen(port, () => {
  console.log(`Serveur démarré sur le port ${port}`);
});
