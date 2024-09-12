const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors("*"));

app.listen(3080, () => {
  console.log("Serveur à l'écoute sur le port 3080");
});
