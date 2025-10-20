const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const fetch = require('node-fetch'); // npm install node-fetch@2

const app = express();
const PORT = 3005;

// === ⚠️ Secrets (mettre en env variables en prod) ===
const SECRET_KEY = process.env.SECRET_KEY || "maCleSecreteJWT";
const T24_USER = process.env.T24_USER || "GTSUSER";
const T24_PASS = process.env.T24_PASS || "1234567";

// === URL Ngrok local API ===
const NGROK_API = "http://127.0.0.1:4040/api/tunnels";

app.use(express.json());
app.use(cors({
  origin: "http://localhost:59222",
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// === Base simulée login ===
const localCredentials = [
  { email: "msalifou@orangebank.ci", password: "1234567" },
  { email: "martial.ehui@orangebank.ci", password: "1234567" } 
];

const activeTokens = new Set();

// === LOGIN ===
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "email et password requis" });

  const cred = localCredentials.find(c => c.email === email && c.password === password);
  if (!cred) return res.status(401).json({ error: "Email ou mot de passe incorrect" });

  const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: "5m" });
  activeTokens.add(token);

  res.json({ login: cred.email, email: cred.email, token });
});

// === Middleware token ===
function verifyToken(req, res, next) {
  const auth = req.headers['authorization'];
  const token = auth?.split(' ')[1];

  if (!token) return res.status(403).json({ error: "Token manquant" });
  if (!activeTokens.has(token)) return res.status(401).json({ error: "Token invalide ou expiré" });

  try {
    req.user = jwt.verify(token, SECRET_KEY);
    activeTokens.delete(token);
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

// === Attendre que Ngrok soit prêt avant d'utiliser l'URL ===
async function getNgrokUrl(retries = 10, delay = 1000) {
  for (let i = 0; i < retries; i++) {
    try {
      const resp = await fetch(NGROK_API);
      const data = await resp.json();
      const httpTunnel = data.tunnels.find(t => t.public_url.startsWith("http"));
      if (httpTunnel) return httpTunnel.public_url;
    } catch (err) {
      // Ngrok pas encore prêt
    }
    await new Promise(r => setTimeout(r, delay));
  }
  throw new Error("Ngrok non trouvé après plusieurs tentatives");
}

// === Appel API T24 ===
async function fetchAccountsFromT24(email) {
  try {
    const ngrokUrl = await getNgrokUrl();
    const url = `${ngrokUrl}/OBAMobApi/api/v1.0.0/party/user/userId/${T24_USER}?Email=${encodeURIComponent(email)}`;
    console.log("[FETCH T24] URL:", url);

    const resp = await fetch(url, {
      method: "GET",
      headers: {
        "Accept": "application/json",
        "Authorization": "Basic " + Buffer.from(`${T24_USER}:${T24_PASS}`).toString("base64")
      }
    });

    const text = await resp.text();
    if (!resp.ok) throw new Error(`Erreur API T24 ${resp.status}: ${text}`);
    const data = JSON.parse(text);
    return data.body || [];
  } catch (err) {
    console.error("fetchAccountsFromT24 error:", err.message);
    throw err;
  }
}

// === API comptes ===
app.get('/api/user', verifyToken, async (req, res) => {
  const email = req.query.email;
  if (!email) return res.status(400).json({ error: "email requis" });

  try {
    const users = await fetchAccountsFromT24(email);
    const newToken = jwt.sign({ email }, SECRET_KEY, { expiresIn: "5m" });
    activeTokens.add(newToken);
    res.json({ users, token: newToken });
  } catch (err) {
    res.status(500).json({ error: "Erreur récupération comptes T24" });
  }
});

// === Reset password ===
app.put('/api/reset-password', verifyToken, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: "userId requis" });

  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let newPassword = '';
  while (newPassword.length < 8) {
    const randChar = chars.charAt(Math.floor(Math.random() * chars.length));
    if (newPassword.length === 0 || randChar !== newPassword[newPassword.length - 1]) {
      newPassword += randChar;
    }
  }

  try {
    const ngrokUrl = await getNgrokUrl();
    const timestamp = Date.now();
    const t24Url = `${ngrokUrl}/OBAMobApi/api/v1.0.0/party/user/passwordreset/${timestamp}`;
    const t24Payload = { body: { userlogin: userId, userPassword: newPassword } };

    const resp = await fetch(t24Url, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Basic " + Buffer.from(`${T24_USER}:${T24_PASS}`).toString("base64")
      },
      body: JSON.stringify(t24Payload)
    });

    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || "Erreur réinitialisation T24");

    res.json({
      message: `Mot de passe réinitialisé pour ${userId}`,
      newPassword,
      t24Response: data,
      token: jwt.sign({ userId }, SECRET_KEY, { expiresIn: "5m" })
    });

  } catch (err) {
    console.error("[RESET PASSWORD] Erreur:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// === Route protégée ===
app.get('/api/nextpage', verifyToken, (req, res) => {
  const newToken = jwt.sign({ email: req.user.email }, SECRET_KEY, { expiresIn: "5m" });
  activeTokens.add(newToken);
  res.json({ token: newToken, info: "Page suivante accessible" });
});

// === Lancement serveur ===
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
