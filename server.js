import 'dotenv/config';

import bcrypt from 'bcrypt';
import express from 'express';
import sqlite3v from 'sqlite3';
import multer from 'multer';
import path from 'path';
import { body, validationResult } from 'express-validator';
import cors from 'cors';

import rateLimit from 'express-rate-limit';

// NEU: Imports für JWT und Logger
import jwt from 'jsonwebtoken'; 
import winston, { format } from 'winston';
const { combine, timestamp, printf, colorize } = format;

// VORHER:
// GEHEIMNISSE
// const JWT_SECRET = 'Ein_Sehr_Geheimer_Schluessel_Fuer_SafeSpeak_Den_Niemand_Errät_ABC123';

// NACHHER (den Schlüssel aus der .env-Datei lesen):
// GEHEIMNISSE
const JWT_SECRET = process.env.JWT_SECRET;
const saltRounds = 10;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 Minuten
    max: 5, // Maximal 5 Versuche pro IP-Adresse innerhalb des Fensters
    standardHeaders: true, // Fügt die Rate-Limit-Header (z.B. X-RateLimit-Limit) hinzu
    legacyHeaders: false, // Deaktiviert die X-RateLimit-*-Header (optional, aber modern)
    message: async (req, res) => {
        const ip = req.ip || req.connection.remoteAddress;
        logger.warn(`BRUTE FORCE ABGEWEHRT: IP ${ip} hat zu viele Login-Versuche gestartet.`);
        return res.status(429).json({
            error: "Zu viele Anmeldeversuche. Bitte versuche es in 15 Minuten erneut."
        });
    },
    // WICHTIG: Sollte verhindern, dass der Limiter bei falschen Anmeldeversuchen zurückgesetzt wird.
    skipSuccessfulRequests: true, 
});

// ---------------------------------
// LOGGER KONFIGURATION
// ---------------------------------
const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level}]: ${message}`;
});

const logger = winston.createLogger({
  level: 'info',
  format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), logFormat),
  transports: [
    new winston.transports.Console({ format: combine(colorize(), logFormat) }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
  ],
  exitOnError: false, 
});

const app = express();
const port = process.env.PORT || 3000;

// MIDDLEWARE
app.use(cors()); 
app.use(express.json());

// MULTER KONFIGURATION
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); 
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// ---------------------------------
// DATENBANK UND INITIALISIERUNG
// ---------------------------------
const db = new sqlite3v.Database('safespeak.db', (err) => {
    if (err) {
        logger.error('Fehler beim Verbinden mit der Datenbank:', err.message); // KORREKTUR: logger.error
    } else {
        logger.info('Erfolgreich mit der SafeSpeak-Datenbank verbunden.'); // KORREKTUR: logger.info
        initialize(); 
    }
});

function initialize() {
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        `, (err) => {
            if (err) {
                logger.error(`Fehler beim Erstellen der Tabelle 'users': ${err.message}`);
            } else {
                logger.info("Tabelle 'users' ist bereit.");
            }
        });

        db.run(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT,
                file_path TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        `, (err) => {
            if (err) {
                logger.error(`Fehler beim Erstellen der Tabelle 'messages': ${err.message}`);
            } else {
                logger.info("Tabelle 'messages' ist bereit.");
            }
        });
    });
}
// Zusätzliche/doppelte Initialisierungsblöcke entfernt, da initialize() alles abdeckt.

// HELFER-FUNKTION
function getUserId(username, callback) {
    db.get(`SELECT id FROM users WHERE username = ?`, [username], (err, row) => {
        if (err) {
            callback(err, null);
        } else if (row) {
            callback(null, row.id);
        } else {
            callback(new Error('Benutzer nicht gefunden.'), null);
        }
    });
}

// ---------------------------------
// JWT VERIFIZIERUNGS-MIDDLEWARE
// ---------------------------------
function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) {
        logger.warn(`Autorisierung fehlgeschlagen: Kein Token gefunden (IP: ${req.ip})`);
        return res.status(401).json({ message: 'Zugriff verweigert. Token fehlt.' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            logger.warn(`Autorisierung fehlgeschlagen: Ungültiges oder abgelaufenes Token (IP: ${req.ip})`);
            return res.status(403).json({ message: 'Zugriff verweigert. Token ist ungültig oder abgelaufen.' });
        }
        
        req.user = user; 
        next(); 
    });
}

// ---------------------------------
// ROUTEN
// ---------------------------------

// Benutzer registrieren
app.post('/register', 
    [
        body('username')
            .isString().withMessage('Benutzername muss ein Text sein.').isLength({ min: 3 }).withMessage('Benutzername muss mindestens 3 Zeichen lang sein.')
            .matches(/^[a-zA-Z0-9_]+$/).withMessage('Benutzername darf nur Buchstaben, Zahlen und Unterstriche enthalten.').trim().escape(), 
        body('password')
            .isLength({ min: 8 }).withMessage('Passwort muss mindestens 8 Zeichen lang sein.')
    ],
    async (req, res) => { 
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn(`Registrierung abgelehnt. Validierungsfehler: ${errors.array({ onlyFirstError: true })[0].msg} für Benutzername: ${req.body.username}`);
            return res.status(400).json({ errors: errors.array({ onlyFirstError: true })[0].msg });
        }
        
        const { username, password } = req.body;

        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        logger.warn(`Registrierung fehlgeschlagen. Username existiert bereits: ${username}`);
                        return res.status(400).json({ error: "Registrierung fehlgeschlagen. Username existiert bereits." });
                    }
                    logger.error(`Fehler bei der Registrierung von ${username}: ${err.message}`);
                    return res.status(500).json({ error: "Ein unbekannter Fehler ist aufgetreten." });
                }
                logger.info(`NEUER BENUTZER: ${username} (ID: ${this.lastID}) erfolgreich registriert.`);
                res.json({ message: "Benutzer erfolgreich registriert!", userId: this.lastID });
            });

        } catch (hashError) {
            logger.error("Fehler beim Hashing während der Registrierung:", hashError);
            res.status(500).json({ error: "Fehler beim Verarbeiten des Passworts." });
        }
    } 
);


// Benutzer anmelden
app.post('/login', loginLimiter, (req, res) => {
    // Hier wäre der Platz für den loginLimiter, falls du ihn implementiert hast.
    const { username, password } = req.body;

    db.get("SELECT id, password FROM users WHERE username = ?", [username], async (err, row) => {
        if (err) {
            logger.error(`Datenbankfehler beim Login für Nutzer ${username}: ${err.message}`);
            return res.status(500).json({ error: "Ein interner Fehler ist aufgetreten." });
        }
        
        if (!row) {
             logger.warn(`Fehlgeschlagener Login-Versuch (User nicht existent): ${username}`);
            return res.status(401).json({ error: "Anmeldung fehlgeschlagen. Ungültiger Benutzername oder Passwort." });
        }

        const storedHash = row.password;

        try {
            const match = await bcrypt.compare(password, storedHash);

            if (match) {
                const token = jwt.sign(
                    { userId: row.id, username: username }, 
                    JWT_SECRET, 
                    { expiresIn: '24h' } 
                );
                
                logger.info(`ERFOLGREICHER LOGIN. Nutzer-ID: ${row.id} (${username}). Token generiert.`);
                
                res.json({ 
                    message: "Anmeldung erfolgreich!", 
                    userId: row.id,
                    token: token 
                });
            } else {
                logger.warn(`Fehlgeschlagener Login-Versuch (Passwort falsch): ${username}`);
                res.status(401).json({ error: "Anmeldung fehlgeschlagen. Ungültiger Benutzername oder Passwort." });
            }
        } catch (compareError) {
            logger.error(`Fehler beim Passwortvergleich für ${username}: ${compareError}`);
            res.status(500).json({ error: "Ein interner Fehler ist aufgetreten." });
        }
    });
});


// Nachricht senden (JETZT GESCHÜTZT UND KORREKT)
app.post('/send', 
    verifyToken, // NEU: Token-Prüfung hinzugefügt
    upload.single('file'), 
    [
        // senderUsername wird aus dem Token geholt, nur receiverUsername benötigt Validierung
        body('receiverUsername').trim().escape(),
        body('content')
            .optional().isLength({ max: 2000 }).withMessage('Nachricht ist zu lang (max. 2000 Zeichen).')
            .escape() 
    ],
    
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn(`Senden abgelehnt. Validierungsfehler: ${errors.array({ onlyFirstError: true })[0].msg}.`);
            return res.status(400).json({ errors: errors.array({ onlyFirstError: true })[0].msg });
        }
        
        const senderUsername = req.user.username; // KORREKTUR: Sicher aus dem Token geholt
        const { receiverUsername, content } = req.body;
        const filePath = req.file ? req.file.path : null;

        getUserId(senderUsername, (err, senderId) => {
            if (err) {
                logger.error(`Kritischer Fehler: Sender ${senderUsername} aus Token nicht in DB.`);
                return res.status(500).send({ message: 'Interner Autorisierungsfehler.' });
            }
            getUserId(receiverUsername, (err, receiverId) => {
                if (err) {
                    logger.warn(`Sendeversuch fehlgeschlagen: Empfänger ${receiverUsername} nicht gefunden.`);
                    return res.status(404).send({ message: `Empfänger-Benutzername '${receiverUsername}' nicht gefunden.` });
                }
                db.run(`INSERT INTO messages (sender_id, receiver_id, content, file_path) VALUES (?, ?, ?, ?)`, 
                    [senderId, receiverId, content, filePath], 
                    function(err) {
                    if (err) {
                        logger.error(`Fehler beim Senden der Nachricht von ${senderUsername} an ${receiverUsername}: ${err.message}`);
                        return res.status(500).send({ message: 'Fehler beim Senden der Nachricht.' });
                    }
                    logger.info(`Nachricht gesendet. ID: ${this.lastID}, Sender: ${senderUsername}, Empfänger: ${receiverUsername}. Datei? ${filePath ? 'Ja' : 'Nein'}`);
                    res.status(201).send({ message: 'Nachricht erfolgreich gesendet!', messageId: this.lastID });
                });
            });
        });
    }
);


// Datei-Download (JETZT GESCHÜTZT UND KORREKT)
app.get('/download/:filePath', verifyToken, (req, res) => { // NEU: Token-Prüfung hinzugefügt
    const requestedPath = req.params.filePath; 
    
    // KORREKTUR: clientUsername wird aus dem Token geholt (sicher!)
    const clientUsername = req.user.username; 
    
    getUserId(clientUsername, (err, clientId) => {
        if (err || !clientId) {
            logger.error(`Kritischer Fehler: Download-Client ${clientUsername} aus Token nicht in DB.`);
            return res.status(500).json({ error: 'Interner Autorisierungsfehler.' });
        }
        
        db.get(`
            SELECT * FROM messages 
            WHERE file_path = ? AND (sender_id = ? OR receiver_id = ?)
        `, [requestedPath, clientId, clientId], (err, row) => {
            if (err) {
                 logger.error(`Datenbankfehler bei Download-Prüfung für ${clientUsername}: ${err.message}`);
                 return res.status(500).json({ error: 'Interner Serverfehler.' });
            }
            
            if (!row) {
                logger.warn(`Downloadversuch abgelehnt (Zugriff verweigert): ${clientUsername} versuchte ${requestedPath} herunterzuladen.`);
                return res.status(403).json({ error: 'Zugriff verweigert oder Datei nicht gefunden.' });
            }

            const absolutePath = path.resolve(requestedPath);
            res.download(absolutePath, (err) => {
                if (err) {
                    logger.error(`Fehler beim Dateidownload von ${absolutePath} für ${clientUsername}: ${err}`); // KORREKTUR: logger.error
                    res.status(500).json({ error: 'Fehler beim Laden der Datei.' }); 
                } else {
                    logger.info(`Datei erfolgreich heruntergeladen: ${requestedPath} durch Nutzer ${clientUsername}.`); // NEU: Logging des Erfolgs
                }
            });
        });
    });
});


// Nachrichten abrufen (JETZT GESCHÜTZT UND KORREKT)
app.get('/messages', verifyToken, (req, res) => { // NEU: Token-Prüfung hinzugefügt
    // KORREKTUR: user1 (der anfragende Client) wird aus dem Token geholt!
    const user1 = req.user.username; 
    const { user2 } = req.query;

    getUserId(user1, (err, user1Id) => {
        if (err) {
            logger.error(`Kritischer Fehler: Messages-Client ${user1} aus Token nicht in DB.`);
            return res.status(500).send({ message: 'Interner Autorisierungsfehler.' });
        }
        getUserId(user2, (err, user2Id) => {
            if (err) {
                logger.warn(`Nachrichtenabruf fehlgeschlagen: Ziel-Benutzer ${user2} nicht gefunden.`);
                return res.status(404).send({ message: `Benutzer '${user2}' nicht gefunden.` });
            }
            db.all(`
                SELECT * FROM messages 
                WHERE (sender_id = ? AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = ?) 
                ORDER BY timestamp ASC
            `, [user1Id, user2Id, user2Id, user1Id], (err, rows) => {
                if (err) {
                    logger.error(`Fehler beim Nachrichtenabruf zwischen ${user1} und ${user2}: ${err.message}`);
                    return res.status(500).send({ message: 'Fehler beim Abrufen der Nachrichten.' });
                }
                logger.info(`Nachrichtenverlauf abgerufen: ${rows.length} Nachrichten zwischen ${user1} und ${user2}.`);
                res.status(200).json(rows);
            });
        });
    });
});

app.get('/', (req, res) => {
    res.send('Willkommen auf dem SafeSpeak-Server! Die Datenbank ist eingerichtet.');
});


app.listen(port, () => {
    logger.info(`Server läuft auf Port ${port}`); // KORREKTUR: logger.info
});