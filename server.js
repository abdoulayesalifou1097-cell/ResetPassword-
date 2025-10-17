const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch'); // npm install node-fetch@2
const crypto = require('crypto');

const app = express();
const PORT = 3005;
const SECRET_KEY = "maCleSecreteJWT"; // ⚠️ mettre en variable d'env en prod

app.use(express.json());
app.use(cors({
  origin: "http://localhost:59222",
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// === Base simulée minimale pour login ===
const localCredentials = [
  { email: "msalifou@orangebank.ci", password: "1234567" },
  { email: "martial.ehui@orangebank.ci", password: "1234567" } 
];

// === Stockage des tokens actifs ===
const activeTokens = new Set();

// === LOGIN ===
app.post('/api/login', (req, res) => {
  console.log("[LOGIN] Requête login reçue:", req.body);
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email et password requis" });

  const cred = localCredentials.find(c => c.email === email && c.password === password);
  if (!cred) return res.status(401).json({ error: "Email ou mot de passe incorrect" });

  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "5m" });
  activeTokens.add(token);
  console.log("[LOGIN] Token généré:", token);

  res.json({ login: cred.email, email: cred.email, token });
});

// === Middleware pour vérifier et consommer le token ===
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  const token = auth?.split(' ')[1];

  console.log("[VERIFY TOKEN] Token reçu:", token);

  if (!token) return res.status(403).json({ error: "Token manquant" });
  if (!activeTokens.has(token)) return res.status(401).json({ error: "Token invalide ou expiré" });

  try {
    req.user = jwt.verify(token, SECRET_KEY);
    activeTokens.delete(token); // token consommé
    console.log("[VERIFY TOKEN] Token valide pour:", req.user.email);
    next();
  } catch (err) {
    console.error("[VERIFY TOKEN] Erreur:", err.message);
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

// === Helper pour appeler l'API T24 réelle (GET comptes) ===
async function fetchAccountsFromT24(email) {
  try {
    const userId = "GTSUSER";
    const password = "1234567";
    const url = `http://localhost:8085/OBAMobApi/api/v1.0.0/party/user/userId/${userId}?Email=${encodeURIComponent(email)}`;
    console.log("[FETCH T24] URL:", url);

    const resp = await fetch(url, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Authorization": "Basic " + Buffer.from(`${userId}:${password}`).toString("base64")
      }
    });

    const text = await resp.text();
    console.log("[FETCH T24] Réponse brute:", text);

    if (!resp.ok) throw new Error(`Erreur API T24 ${resp.status}: ${text}`);
    const data = JSON.parse(text);
    return data.body || [];
  } catch (err) {
    console.error("fetchAccountsFromT24 error:", err.message);
    throw err;
  }
}

// === API pour récupérer comptes (page ChoixCompte) ===
app.get('/api/user', verifyToken, async (req, res) => {
  const email = req.query.email;
  console.log("[API USER] Requête pour email:", email);

  if (!email) return res.status(400).json({ error: "email requis" });

  try {
    const users = await fetchAccountsFromT24(email);
    console.log("[API USER] Comptes reçus:", users);

    const newToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: "5m" });
    activeTokens.add(newToken);

    res.json({ users, token: newToken });
  } catch (err) {
    console.error("[API USER] Erreur récupération comptes:", err.message);
    res.status(500).json({ error: "Erreur récupération comptes T24" });
  }
});

// === API pour réinitialiser mot de passe T24 ===
app.put('/api/reset-password', verifyToken, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: "userId requis" });

    // Génération mot de passe aléatoire 8 caractères sans répétition consécutive
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let newPassword = '';
    while (newPassword.length < 8) {
      const randChar = chars.charAt(Math.floor(Math.random() * chars.length));
      if (newPassword.length === 0 || randChar !== newPassword[newPassword.length - 1]) {
        newPassword += randChar;
      }
    }

    // Création du timestamp dynamique (équivalent {{$timestamp}})
    const timestamp = Date.now();
    const t24Url = `http://localhost:8085/OBAMobApi/api/v1.0.0/party/user/passwordreset/${timestamp}`;
    const t24Payload = { 
      body: { 
        userlogin: userId, 
        userPassword: newPassword 
      } 
    };

    console.log("[RESET PASSWORD] Appel T24:", t24Url, "userId:", userId, "nouveau mdp:", newPassword);

    const resp = await fetch(t24Url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Basic " + Buffer.from("GTSUSER:1234567").toString("base64")
      },
      body: JSON.stringify(t24Payload)
    });

    const data = await resp.json();
    console.log("[RESET PASSWORD] Réponse T24:", data);

    if (!resp.ok) throw new Error(data.error || "Erreur réinitialisation T24");

    res.json({
      message: `Félicitations, mot de passe réinitialisé avec succès pour ${userId}`,
      newPassword,
      t24Response: data,
      token: jwt.sign({ userId }, SECRET_KEY, { expiresIn: "5m" })
    });

  } catch (err) {
    console.error("[RESET PASSWORD] Erreur:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// === Exemple route protégée page suivante ===
app.get('/api/nextpage', verifyToken, (req, res) => {
  const newToken = jwt.sign({ email: req.user.email }, SECRET_KEY, { expiresIn: "5m" });
  activeTokens.add(newToken);
  res.json({ token: newToken, info: "Page suivante accessible" });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
