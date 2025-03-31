const admin = require("firebase-admin");
const serviceAccount = require("./firebase-config.json"); // Archivo descargado desde Firebase

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

module.exports = { db };
