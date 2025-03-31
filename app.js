require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

// Conexión a MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

db.connect((err) => {
  if (err) {
    console.error("Error al conectar a MySQL:", err);
  } else {
    console.log("Conectado a MySQL");
  }
});

// Middleware para verificar token
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({
      statusCode: 403,
      message: "Token requerido",
    });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({
        statusCode: 401,
        message: "Token inválido",
      });
    }
    req.user = decoded;
    next();
  });
};

// Registro de usuarios
app.post("/api/register", async (req, res) => {
  const { username, password, email, birth_date, fullname } = req.body;

  console.log(req.body);

  if (!username || !password || !email || !birth_date || !fullname) {
    return res.status(400).json({
      statusCode: 400,
      message: "All fields are required",
    });
  }

  const emailRegex = /^[\w-]+(\.[\w-]+)*@([\w-]+\.)+[a-zA-Z]{2,7}$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      statusCode: 400,
      message: "Invalid email format",
    });
  }

  const checkUserQuery = "SELECT * FROM users WHERE username = ? OR email = ?";
  db.query(checkUserQuery, [username, email], async (err, results) => {
    if (err) {
      return res.status(500).json({
        statusCode: 500,
        message: "Error en el servidor",
        error: err,
      });
    }

    if (results.length > 0) {
      return res.status(409).json({
        statusCode: 409,
        message: "User already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = "INSERT INTO users (username, password, email, birth_date, fullname) VALUES (?, ?, ?, ?, ?)";
    db.query(sql, [username, hashedPassword, email, birth_date, fullname], (err, result) => {
      if (err) {
        return res.status(500).json({
          statusCode: 500,
          message: "Error al registrar el usuario",
          error: err,
        });
      }
      res.status(201).json({
        statusCode: 201,
        message: "User registered successfully",
      });
    });
  });
});
app.get("/api/login", (req, res) => {
  const { username, password } = req.query; // Usamos req.query para obtener los parámetros de la URL

  if (!username || !password) {
    return res.status(400).json({
      statusCode: 400,
      message: "All fields are required",
    });
  }

  const sql = "SELECT * FROM users WHERE username = ?";
  db.query(sql, [username], async (err, results) => {
    if (err) {
      return res.status(500).json({
        statusCode: 500,
        message: "Error en el servidor",
      });
    }

    if (results.length === 0) {
      return res.status(401).json({
        statusCode: 401,
        message: "The user or password are wrong",
      });
    }

    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password); // Comparamos la contraseña

    if (!isMatch) {
      return res.status(401).json({
        statusCode: 401,
        message: "The user or password are wrong",
      });
    }

    // Generar token JWT
    const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: "1h" });

    res.status(200).json({
      statusCode: 200,
      message: "The user and password are correct",
      token,
    });
  });
});


// Ruta protegida de prueba
app.get("/api/protected", verifyToken, (req, res) => {
  res.status(200).json({
    statusCode: 200,
    message: "Ruta protegida",
    user: req.user,
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
