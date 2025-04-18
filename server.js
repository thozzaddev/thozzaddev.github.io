require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const { WebhookClient } = require('discord.js');
const cors = require('cors');
const authRouter = express.Router();

const app = express();
const PORT = process.env.PORT || 3000;
const DB_PATH = path.resolve(__dirname, 'database.json');

let db;
let webhookClient;

async function initialize() {
  try {
    const data = await fs.readFile(DB_PATH, 'utf8');
    db = JSON.parse(data);
    
    if (db.settings?.discord_webhook) {
      webhookClient = new WebhookClient({ url: db.settings.discord_webhook });
    }
    
    console.log('✅ Base de données et services initialisés');
  } catch (err) {
    console.error('❌ Erreur d\'initialisation:', err);
    process.exit(1);
  }
}

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    
    const allowedOrigins = [
      'http://localhost',
      'http://127.0.0.1',
      /^http:\/\/localhost:\d+$/
    ];
    
    if (allowedOrigins.some(allowed => {
      return typeof allowed === 'string' 
        ? origin.startsWith(allowed)
        : allowed.test(origin);
    })) {
      return callback(null, true);
    }
    
    return callback(new Error('Origine non autorisée par CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/auth/login', (req, res) => {
  res.status(405).json({
    success: false,
    error: 'METHOD_NOT_ALLOWED',
    message: 'Utilisez POST pour vous connecter'
  });
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

authRouter.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const cleanPassword = password.trim();

    if (process.env.NODE_ENV === 'development') {
      console.log('\n🔐 DEBUG CONNEXION');
      console.log('-----------------');
      console.log(`Username saisi : ${username}`);
      console.log(`Mot de passe saisi (nettoyé) : ${JSON.stringify(cleanPassword)}`);
      console.log(`Longueur : ${cleanPassword.length} caractères`);
    }

    if (!username || !cleanPassword) {
      return res.status(400).json({
        success: false,
        error: 'CREDENTIALS_REQUIRED',
        message: 'Nom d\'utilisateur et mot de passe requis'
      });
    }

    const user = db.users.find(u => u.username === username);
    if (!user) {
      console.warn(`[Auth] Utilisateur inconnu : ${username}`);
      return res.status(401).json({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Identifiants incorrects'
      });
    }

    if (process.env.NODE_ENV === 'development') {
      console.log('\n🔍 COMPARAISON MOT DE PASSE');
      console.log('--------------------------');
      console.log(`Mot de passe stocké    : ${user.password}`);
      console.log(`Mot de passe reçu : "${cleanPassword}"`);
    }

    if (cleanPassword !== user.password) {
      if (process.env.NODE_ENV === 'development') {
        console.warn('\n⚠️ ERREUR COMPARAISON');
        console.warn('-------------------');
        console.warn(`Reçu : "${cleanPassword}" (${Array.from(cleanPassword).map(c => c.charCodeAt(0))})`);
        console.warn(`Attendu : "${user.password}" (${Array.from(user.password).map(c => c.charCodeAt(0))})`);
      }

      return res.status(401).json({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Identifiants incorrects'
      });
    }

    const twoFACode = crypto.randomInt(100000, 999999).toString();
    user.twofa = {
      code: twoFACode,
      expires: new Date(Date.now() + 15 * 60000)
    };

    if (webhookClient) {
      await webhookClient.send({
        content: [
          `🔐 **Code de vérification pour ${user.username}**`,
          ``,
          `🔐 **Code ${twoFACode}**`,
          ``,
          `• 🆔 Identifiant : ${user.id} || <@${user.discord_id}>`,
          `• 📧 Adresse email : ${user.email || 'N/A'}`,
          `• 📍 IPs autorisées : ${user.ip_whitelist.join(', ')}`,
          `• 🧑‍💼 Rôle : ${user.role}`,
          `• 🔑 Token de session : ${user.session?.token || 'N/A'}`,
          `• ⏰ Expiration : ${user.session?.expire || 'N/A'}`,
          ``,
          `♾️ <@1055134168197103656>`,
        ].join('\n'),
        username: '🔐 Authentification France New Life'
      });
    }

    await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2));

    console.log(`[Auth] ${username} authentifié avec succès | 2FA envoyée`);
    
    return res.json({
      success: true,
      requires2FA: user.twofa_enabled,
      userId: user.id,
      username: user.username
    });

  } catch (error) {
    console.error('[Auth] Erreur:', error);
    return res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: process.env.NODE_ENV === 'development' 
        ? error.message 
        : 'Erreur interne du serveur'
    });
  }
});

authRouter.get('/check-ip', (req, res) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  console.log(`[IP Check] Requête reçue depuis: ${clientIP}`);
  
  const allowedIPs = ['::1', '127.0.0.1'];
  
  if (allowedIPs.includes(clientIP)) {
    return res.status(200).json({ 
      authorized: true,
      ip: clientIP,
      message: "Accès autorisé"
    });
  } else {
    console.warn(`[IP Check] Accès refusé pour IP: ${clientIP}`);
    return res.status(403).json({ 
      authorized: false,
      ip: clientIP,
      message: "Accès non autorisé"
    });
  }
});

authRouter.post('/verify-2fa', async (req, res) => {
  try {
    const { userId, code } = req.body;

    // 1. Validation des données
    if (!userId || !code) {
      return res.status(400).json({
        success: false,
        error: 'INVALID_REQUEST',
        message: 'Données de requête invalides'
      });
    }

    // 2. Recherche de l'utilisateur
    const user = db.users.find(u => u.id === userId);
    if (!user || !user.twofa) {
      console.warn(`[2FA] Tentative de vérification avec utilisateur invalide: ${userId}`);
      return res.status(401).json({
        success: false,
        error: 'INVALID_2FA',
        message: 'Processus de vérification invalide'
      });
    }

    // 3. Vérification du code
    if (user.twofa.code !== code || new Date(user.twofa.expires) < new Date()) {
      console.warn(`[2FA] Code invalide ou expiré pour l'utilisateur: ${user.username}`);
      return res.status(401).json({
        success: false,
        error: 'INVALID_2FA_CODE',
        message: 'Code invalide ou expiré'
      });
    }

    // 4. Génération du token de session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    user.session = {
      token: sessionToken,
      expires: new Date(Date.now() + 24 * 3600 * 1000) // 24 heures
    };

    // 5. Nettoyage du 2FA
    delete user.twofa;

    // 6. Sauvegarde en base de données
    await fs.writeFile(DB_PATH, JSON.stringify(db, null, 2));

    console.log(`[Auth] 2FA validé pour ${user.username}`);
    
    // 7. Réponse
    return res.json({
      success: true,
      token: sessionToken,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    console.error('[2FA] Erreur lors de la vérification:', error);
    return res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'Erreur interne du serveur'
    });
  }
});

app.use('/api/auth', authRouter);

// Middleware d'authentification corrigé
async function authenticate(req, res, next) {
  try {
    // 1. Récupération du token
    const authHeader = req.headers.authorization;
    
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        error: 'AUTH_REQUIRED',
        message: 'Authentification requise'
      });
    }

    // 2. Extraction du token Bearer
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'INVALID_TOKEN_FORMAT',
        message: 'Format de token invalide'
      });
    }

    // 3. Vérification du token
    const user = db.users.find(u => u.session?.token === token);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'INVALID_TOKEN',
        message: 'Token invalide'
      });
    }

    // 4. Vérification de l'expiration
    if (new Date(user.session.expires) < new Date()) {
      return res.status(401).json({
        success: false,
        error: 'TOKEN_EXPIRED',
        message: 'Session expirée'
      });
    }

    // 5. Ajout de l'utilisateur à la requête
    req.user = user;
    next();

  } catch (error) {
    console.error('Erreur auth middleware:', error);
    
    // Ne pas envoyer de réponse si déjà envoyée
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        error: 'SERVER_ERROR',
        message: 'Erreur interne du serveur'
      });
    }
  }
}

// Route protégée exemple
app.get('/api/protected-route', authenticate, (req, res) => {
  try {
    // Votre logique de route...
    res.json({
      success: true,
      data: { /* vos données */ }
    });
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR'
    });
  }
});

app.use(express.static(path.join(__dirname, 'public'), (req, res, next) => {
  // Blocage de l'accès direct à dashboard.html
  if (req.path === '/dashboard.html' || req.path === '/dashboard') {
    return res.redirect('/login.html');
  }
  next();
}));

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/dashboard', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'), {
    headers: {
      'Cache-Control': 'no-store'
    }
  });
});

app.get('/api/dashboard', authenticate, (req, res) => {
  res.json({
    success: true,
    data: {
      stats: db.server_stats,
      recentPlayers: db.players.slice(-5).reverse(),
      user: req.user
    }
  });
});

app.get('/api/connections', (req, res) => {
  try {
    const database = require('./database.json');

    const connections = database.users.map(user => {
      return {
        id: user.id,
        username: user.username,
        last_login: user.last_login || new Date().toISOString(),
        ip_whitelist: user.ip_whitelist || [],
        role: user.role,
        discord: user.discord_id || null,
        session_id: user.session?.id || null,
        token: user.session?.token || null,
        expires: user.session?.expires || null,
        play_time: user.play_time || 0,
      };
    });
    
    res.json({
      success: true,
      connections: connections
    });
  } catch (error) {
    console.error('Erreur lors de la récupération des connexions:', error);
    res.status(500).json({
      success: false,
      message: 'Erreur lors de la récupération des connexions'
    });
  }
});

app.use('/api', (err, req, res, next) => {
  console.error('API Error:', err);
  res.status(500).json({
    success: false,
    error: 'SERVER_ERROR',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

app.get('/api/user/:userId', authenticate, async (req, res) => {
  try {
    const user = db.users.find(u => u.id === req.params.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      discord: user.discord_id || null,
      session_id: user.session?.id || null,
      token: user.session?.token || null,
      expires: user.session?.expires || null,
      play_time: user.play_time || 0
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.use((err, req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${req.ip}  10000`);
  console.error('Erreur non gérée:', err);
  res.status(500).json({
    success: false,
    error: 'INTERNAL_ERROR',
    message: 'Une erreur interne est survenue'
  });
  if (req.path.endsWith('.html') && !req.path.endsWith('login.html')) {
    return res.redirect('/login');
  }
  next();
});

initialize().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
    console.log(`🔒 Mode: ${process.env.NODE_ENV || 'development'}`);
    
    console.log('\n📋 INFORMATIONS DE CONNEXION :');
    console.log('-----------------------------');
    
    const adminUser = db.users.find(u => u.role === 'admin');
    
    if (adminUser) {
      console.log(`👤 Username: ${adminUser.username}`);
      console.log(`🔑 Password: admin123 (mot de passe par défaut)`);
      console.log(`📧 Email: ${adminUser.email || 'non spécifié'}`);
      console.log(`role: ${adminUser.role}`);
      console.log(`🔐 2FA activée: ${adminUser.twofa_enabled ? 'Oui' : 'Non'}`);
    } else {
      console.log('❌ Aucun utilisateur admin trouvé dans database.json');
    }
    
    console.log('\n🌐 URLs:');
    console.log(`- Page de login: http://localhost:${PORT}/login.html`);
    console.log(`- API: http://localhost:${PORT}/api/auth/login`);
    console.log(`- API: http://localhost:${PORT}/api/connections`);
    
    console.log('\n⚠️ ATTENTION: Ces identifiants sont pour le développement seulement');
  });
});