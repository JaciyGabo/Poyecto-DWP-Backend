import express from "express";
import cors from "cors";
import admin from "firebase-admin";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import axios from "axios";
import translate from "google-translate-api-x";
import speakeasy from "speakeasy";

dotenv.config();

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(express.json());
app.use(cors());
const blacklistedTokens = new Set();



admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_CREDENTIALS)),
});

const db = admin.firestore();
const SECRET_KEY = process.env.JWT_SECRET;
const SALT_ROUNDS = 10;

// Configuración de nodemailer
const transporter = nodemailer.createTransport({
  service: "gmail",
  host: "smtp.gmail.com",
  port: 587,
  secure: false, // Cambia a false si usas el puerto 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false, // Evita problemas con certificados SSL
  },
});

// Generar un token de 5 dígitos
function generateToken() {
  return Math.floor(10000 + Math.random() * 90000).toString(); // Generar un número aleatorio de 5 dígitos
}

// Middleware para verificar el token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(403).json({ message: "Token requerido" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Token inválido" });
    req.user = decoded;
    req.userEmail = decoded.email;
    next();
  });
};

// Endpoint para solicitar un código de verificación
const sendVerificationEmail = async (email, token) => {
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Verificación de cuenta",
    text: `Tu código de verificación es: ${token}`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Correo enviado a:", email);
  } catch (error) {
    console.error("Error al enviar el correo:", error);
  }
};

app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userData = userDoc.data();
    const secret = userData.mfaSecret;

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: "base32",
      token: otp,
      window: 1,
    });

    if (verified) {
      // 🔹 Actualizar el campo "verificado" a 1 en Firestore
      await userRef.update({ verificado: 1 });

      return res.status(200).json({ message: "Código verificado con éxito" });
    } else {
      return res.status(401).json({ message: "Código incorrecto" });
    }
  } catch (error) {
    console.error("Error en la verificación OTP:", error);
    return res.status(500).json({ message: "Error en el servidor" });
  }
});


// Endpoint para obtener datos curiosos y traducirlos
app.get("/events", (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");

  const sendFact = async () => {
    try {
      // Obtener datos curiosos de la API externa
      const response = await axios.get("https://catfact.ninja/fact");
      const fact = response.data.fact;

      //console.log("Datos curiosos obtenidos:", fact);

      // Traducir el dato al español
      const translated = await translate(fact, { to: "es" });

      // Verificar si la conexión sigue abierta antes de enviar el dato
      if (!res.writableEnded) {
        res.write(`data: ${translated.text}\n\n`);
      }
    } catch (error) {
      console.error("Error obteniendo datos:", error);
      if (!res.writableEnded) {
        res.write("data: Error al obtener datos\n\n");
      }
    }
  };

  // Enviar un dato inmediatamente al conectar
  sendFact();

  // Luego, seguir enviando datos cada 10 segundos
  const interval = setInterval(sendFact, 20000);

  // Manejar cuando el cliente cierra la conexión
  req.on("close", () => {
    clearInterval(interval);
    console.log("Conexión SSE cerrada");
  });
});

// Endpoint para obtener una imagen de un gato
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body;

  try {
    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(400).json({ message: "El usuario ya existe" });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const secret = speakeasy.generateSecret({ length: 20 });

    await userRef.set({
      username,
      email,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      mfaSecret: secret.base32,
      verificado: 0
    });

    res.status(201).json({ message: "Registro exitoso", secret: secret.otpauth_url });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error en el registro", error: error.message });
  }
});

// Endpoint para iniciar sesión
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(401).json({ message: "Credenciales incorrectas" });
    }

    const userData = userDoc.data();
    //console.log(userData.role)

    const isMatch = await bcrypt.compare(password, userData.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Credenciales incorrectas" });
    }

    const token = jwt.sign({ email, username: userData.username }, SECRET_KEY, { expiresIn: "1hr" });

    if (userData.verificado === 0) {
      return res.status(200).json({token, requiresMFA: true, message: "Verifica tu cuenta" });
    }
    res.json({ token, message: "Inicio de sesión exitoso" });


  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error en el inicio de sesión", error: error.message });
  }
});

// Endpoint para verificar el token
app.get("/protected", verifyToken, (req, res) => {
  res.json({ message: "Acceso autorizado", user: req.user });
});

// Endpoint para verificar el correo
app.post("/verify-email", async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: "Falta el correo" });
  }

  try {
    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Correo no registrado" });
    }

    const token = generateToken();

    await userRef.update({ token });
    await sendVerificationEmail(email, token);

    res.status(200).json({ message: "Correo verificado" });
  } catch (error) {
    console.error("Error al verificar el correo:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Endpoint para verificar el token de cambio de contraseña
app.post('/verify-token', async (req, res) => {
  const { email, token } = req.body;

  if (!email || !token) {
    return res.status(400).json({ message: "Faltan datos" });
  }

  try {
    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Correo no registrado" });
    }

    const userData = userDoc.data();

    if (userData.token !== token) {
      return res.status(401).json({ message: "Token incorrecto" });
    }

    await userRef.update({ token: "" });

    res.status(200).json({ message: "Cuenta verificada con éxito" });
  } catch (error) {
    console.error("Error al verificar el token:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Endpoint para actualizar la contraseña
app.post('/update-pass', async (req, res) => {
  const { email, pass } = req.body;

  if (!email || !pass) {
    return res.status(400).json({ message: "Faltan datos" });
  }

  try {
    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Correo no registrado" });
    }

    const hashedPassword = await bcrypt.hash(pass, SALT_ROUNDS);
    await userRef.update({ password: hashedPassword });

    res.status(200).json({ message: "Contraseña actualizada con éxito" });
  } catch (error) {
    console.error("Error al verificar el token:", error);
    res.status(500).json({ message: "Error en el servidor" });
  }
});

// Endpoint para cerrar sesión
app.post("/logout", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (token) {
    blacklistedTokens.add(token); // Agregar token a la lista negra
    res.json({ message: "Cierre de sesión exitoso" });
  } else {
    res.status(400).json({ message: "No se proporcionó un token" });
  }
});

// Endpoint para guardar una imagen favorita
app.post("/save-favorite", verifyToken, async (req, res) => {
  const { imageUrl, text, hash } = req.body;
  const email = req.userEmail; // Obtener el correo del token decodificado
  console.log("hash:", hash);
  console.log("email:", email);
  
  if (!imageUrl || !text) {
    return res.status(400).json({ message: "Faltan datos" });
  }

  try {
    // Verificar que el usuario existe
    const userDoc = await db.collection("users").doc(email).get();
    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // Verificar si ya existe en la colección de favoritos
    const favoritesRef = db.collection("favorites");
    const existingFavorite = await favoritesRef
      .where("hash", "==", hash)
      .where("userEmail", "==", email)
      .limit(1)
      .get();

    if (!existingFavorite.empty) {
      return res.status(400).json({ message: "Imagen ya en favoritos" });
    }

    // Guardar en la nueva colección
    await favoritesRef.add({
      url: imageUrl,
      text,
      hash, 
      userEmail: email,
      createdAt: new Date() // Opcional: añadir timestamp
    });

    res.status(200).json({ message: "Imagen guardada como favorita" });
  } catch (error) {
    console.error("Error al guardar la imagen:", error);
    res.status(500).json({ message: "Error al guardar la imagen", error: error.message });
  }
});

// Endpoint para eliminar una imagen favorita
app.delete("/remove-favorite/:favoriteId", verifyToken, async (req, res) => {
  const { favoriteId } = req.params;
  const email = req.userEmail; // Email del usuario autenticado

  try {
    // 1. Verificar que el favorito existe y pertenece al usuario
    const favoriteRef = db.collection("favorites").doc(favoriteId);
    const favoriteDoc = await favoriteRef.get();

    if (!favoriteDoc.exists) {
      return res.status(404).json({ message: "Favorito no encontrado" });
    }

    if (favoriteDoc.data().userEmail !== email) {
      return res.status(403).json({ message: "No tienes permisos para eliminar este favorito" });
    }

    // 2. Eliminar el documento
    await favoriteRef.delete();

    res.status(200).json({ message: "Favorito eliminado correctamente" });
  } catch (error) {
    console.error("Error al eliminar favorito:", error);
    res.status(500).json({ message: "Error al eliminar favorito", error: error.message });
  }
});

// Endpoint para agregar un amigo
app.post("/add-friend", verifyToken, async (req, res) => {
  const { email } = req.body;
  const userEmail = req.userEmail; // Obtener el correo del token decodificado

  if (!email) {
    return res.status(400).json({ message: "Falta el correo" });
  }

  if (email === userEmail) {
    return res.status(400).json({ message: "No puedes enviarte una solicitud a ti mismo" });
  }

  try {
    const userDoc = await db.collection("users").doc(email).get();
    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // Verificar si ya son amigos
    const userFriendsDoc = await db.collection("userFriends").doc(userEmail).get();
    const userFriends = userFriendsDoc.exists ? userFriendsDoc.data().friends || [] : [];

    if (userFriends.includes(email)) {
      return res.status(400).json({ message: "Este usuario ya es tu amigo" });
    }

    // Verificar si ya existe una solicitud pendiente
    const existingRequest = await db.collection("friendRequests")
      .where("fromUser", "==", userEmail)
      .where("toUser", "==", email)
      .where("status", "==", "pending")
      .get();

    if (!existingRequest.empty) {
      return res.status(400).json({ message: "Ya existe una solicitud pendiente" });
    }

    // Crear la solicitud de amistad
    await db.collection("friendRequests").add({
      fromUser: userEmail,
      toUser: email,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(200).json({ message: "Solicitud de amistad enviada" });
  } catch (error) {
    console.error("Error al enviar solicitud de amistad:", error);
    res.status(500).json({ message: "Error al enviar solicitud", error: error.message });
  }
});

// Endpoint para enviar solicitudes de amistad     
app.get("/friend-requests", verifyToken, async (req, res) => {
  const userEmail = req.userEmail; // Obtener el correo del token decodificado

  if (!userEmail) {
    return res.status(400).json({ message: "Usuario no autenticado" });
  }

  try {
    const requestsSnapshot = await db.collection("friendRequests")
      .where("toUser", "==", userEmail)
      .where("status", "==", "pending")
      .get();

    if (requestsSnapshot.empty) {
      return res.status(200).json({ message: "No tienes solicitudes pendientes" });
    }

    const requests = requestsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.status(200).json({ requests });
  } catch (error) {
    console.error(`Error al obtener solicitudes de amistad para ${userEmail}:`, error);
    res.status(500).json({ message: "Error al obtener solicitudes", error: error.message });
  }
});

// Endpoint para aceptar solicitudes de amistad
app.post("/accept-request", verifyToken, async (req, res) => {
  const { fromUser } = req.body; // El usuario que envió la solicitud
  const userEmail = req.userEmail;

  try {
    const requestSnapshot = await db.collection("friendRequests")
      .where("fromUser", "==", fromUser)
      .where("toUser", "==", userEmail)
      .where("status", "==", "pending")
      .get();

    if (requestSnapshot.empty) {
      return res.status(404).json({ message: "Solicitud no encontrada" });
    }

    const requestDoc = requestSnapshot.docs[0]; // Tomar la primera coincidencia
    const requestRef = requestDoc.ref;

    // Usar transacción para procesar la solicitud
    await db.runTransaction(async (transaction) => {
      transaction.update(requestRef, { status: "accepted" });

      const userFriendsRef = db.collection("userFriends").doc(userEmail);
      const fromUserFriendsRef = db.collection("userFriends").doc(fromUser);

      transaction.set(userFriendsRef, {
        friends: admin.firestore.FieldValue.arrayUnion(fromUser)
      }, { merge: true });

      transaction.set(fromUserFriendsRef, {
        friends: admin.firestore.FieldValue.arrayUnion(userEmail)
      }, { merge: true });
    });

    res.status(200).json({ message: "Solicitud aceptada correctamente" });
  } catch (error) {
    console.error("Error al aceptar solicitud:", error);
    res.status(500).json({ message: "Error al aceptar solicitud", error: error.message });
  }
});

// Endpoint para obtener la lista de amigos con username
app.get("/friends", verifyToken, async (req, res) => {
  const userEmail = req.userEmail;

  try {
    const userFriendsDoc = await db.collection("userFriends").doc(userEmail).get();

    const friendsEmails = userFriendsDoc.exists ? userFriendsDoc.data().friends || [] : [];

    if (friendsEmails.length === 0) {
      return res.status(200).json({ friends: [] });
    }

    // Obtener los usuarios con esos correos
    const usersRef = db.collection("users");
    const friendsQuery = await Promise.all(
      friendsEmails.map(async (email) => {
        const userDoc = await usersRef.doc(email).get();
        if (userDoc.exists) {
          const userData = userDoc.data();
          return {
            email,
            username: userData.username || "", // Puedes poner un fallback si falta
          };
        } else {
          return { email, username: "" }; // En caso de que no exista el documento
        }
      })
    );
    
    console.log("Amigos obtenidos:", friendsQuery);

    res.status(200).json({ friends: friendsQuery });
  } catch (error) {
    console.error("Error al obtener amigos:", error);
    res.status(500).json({ message: "Error al obtener amigos", error: error.message });
  }
});

app.get("/user-data", verifyToken, async (req, res) => {
  const userEmail = req.userEmail; // Obtener el correo del token decodificado

  try {
    const userDoc = await db.collection("users").doc(userEmail).get();

    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    const userData = userDoc.data();
    res.status(200).json({ userData });
  } catch (error) {
    console.error("Error al obtener datos del usuario:", error);
    res.status(500).json({ message: "Error al obtener datos del usuario", error: error.message });
  }
}
);

app.post("/update-profile", verifyToken, async (req, res) => {
  const { username, password } = req.body;
  const userEmail = req.userEmail; // Obtenido del verifyToken

  try {
    // 1. Validar datos de entrada
    if (!username || username.length < 3) {
      return res.status(400).json({ message: "El nombre de usuario debe tener al menos 3 caracteres" });
    }

    if (password && password.length < 3) {
      return res.status(400).json({ message: "La contraseña debe tener al menos 3 caracteres" });
    }

    // 2. Crear objeto con los campos a actualizar
    const updateData = { username };
    
    // Solo actualizar contraseña si se proporcionó
    if (password) {
      // Hashear la nueva contraseña antes de guardarla
      const hashedPassword = await bcrypt.hash(password, 10);
      updateData.password = hashedPassword;
    }

    // 3. Actualizar en Firestore
    const userRef = db.collection("users").doc(userEmail);
    
    // Actualización parcial (solo los campos que cambian)
    await userRef.update(updateData);

    // 4. Responder con éxito
    res.status(200).json({ 
      message: "Perfil actualizado correctamente",
      updatedFields: Object.keys(updateData)
    });

  } catch (error) {
    console.error("Error al actualizar perfil:", error);
    
    // Manejar errores específicos
    if (error.code === 'NOT_FOUND') {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    
    res.status(500).json({ 
      message: "Error al actualizar perfil",
      error: error.message 
    });
  }
});

// Endpoint para compartir una foto con un amigo
app.post("/share-photo", verifyToken, async (req, res) => {
  const { toUser, photoUrl, text } = req.body;
  const fromUser = req.userEmail; // Usuario que envía la foto

  if (!toUser || !photoUrl) {
    return res.status(400).json({ message: "Faltan datos obligatorios" });
  }

  if (toUser === fromUser) {
    return res.status(400).json({ message: "No puedes compartir una foto contigo mismo" });
  }

  try {
    // Verificar si el destinatario existe
    const userDoc = await db.collection("users").doc(toUser).get();
    if (!userDoc.exists) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }

    // Verificar si son amigos antes de compartir la foto
    const userFriendsDoc = await db.collection("userFriends").doc(fromUser).get();
    const friends = userFriendsDoc.exists ? userFriendsDoc.data().friends || [] : [];

    if (!friends.includes(toUser)) {
      return res.status(403).json({ message: "Solo puedes compartir fotos con amigos" });
    }

    // Guardar la foto compartida en Firestore
    await db.collection("sharedPhotos").add({
      fromUser,
      toUser,
      photoUrl,
      text: text || "",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.status(200).json({ message: "Foto compartida exitosamente" });
  } catch (error) {
    console.error("Error al compartir foto:", error);
    res.status(500).json({ message: "Error al compartir foto", error: error.message });
  }
});

app.get("/my-cats", verifyToken, async (req, res) => {
  const userEmail = req.userEmail; // Usuario actual (destinatario)

  try {
    const sharedPhotosSnapshot = await db.collection("sharedPhotos")
      .where("toUser", "==", userEmail) // Solo fotos donde el usuario es el destinatario
      .orderBy("createdAt", "desc")
      .get();

    const sharedPhotos = sharedPhotosSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.status(200).json({ sharedPhotos });
  } catch (error) {
    console.error("Error al obtener fotos compartidas:", error);
    res.status(500).json({ message: "Error al obtener fotos compartidas", error: error.message });
  }
});

app.get("/favorite-cats", verifyToken, async (req, res) => {
  const userEmail = req.userEmail;
  const { lastVisible } = req.query;

  try {
    let query = db.collection("favorites")
      .where("userEmail", "==", userEmail)
      .orderBy("createdAt", "desc")
      .limit(10);

    if (lastVisible) {
      const lastDoc = await db.collection("favorites").doc(lastVisible).get();
      if (lastDoc.exists) {
        query = query.startAfter(lastDoc);
      }
    }

    const favoritesSnapshot = await query.get();
    const favorites = favoritesSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));



    res.status(200).json({
      favorites,
      lastVisible: favoritesSnapshot.docs.length > 0 ?
        favoritesSnapshot.docs[favoritesSnapshot.docs.length - 1].id : null
    });
  } catch (error) {
    console.error("Error al obtener gatos favoritos:", error);
    res.status(500).json({
      message: "Error al obtener gatos favoritos",
      error: error.code || error.message
    });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Servidor corriendo en http://localhost:${PORT}`));
