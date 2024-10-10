const express = require('express');
const mariadb = require('mariadb');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(cors());

app.get('/', (req, res) => {});

app.use(express.json());

//connexion à la BDD
const pool = mariadb.createPool({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'Test Logs',
  connectionLimit: 10,
});

//test de la connexion
pool
  .getConnection()
  .then((conn) => {
    console.log('Connected to database');
    conn.release();
  })
  .catch((err) => {
    console.error('Error connecting to database', err);
  });

//post des identifiants
app.post('/login', async (req, res) => {
  console.log(req.body);

  const { user } = req.body;

  const { nom, prenom, ville, codepostal, email, motdepasse } = user;

  try {
    const conn = await pool.getConnection();
    const insert = await conn.query(
      'INSERT INTO Identifiants (nom, prenom, ville, codepostal, email, motdepasse) VALUES (?, ?, ?, ?, ?, ?)',
      [nom, prenom, ville, codepostal, email, motdepasse]
    );
    console.log('User added to database');
    conn.release();
  } catch (err) {
    console.error('Error adding user to database', err);
  }
});

app.listen(port, () => {
  console.log('Server started on port ' + port);
});
