const jwt = require("jsonwebtoken");

function decodeToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(403).json({ error: "Token manquant" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Toutes les infos du token sont ici
    next();
  } catch (err) {
    return res.status(401).json({ error: "Jeton invalide ou expiré" });
  }
}

module.exports = decodeToken;
