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

const tf = require('@tensorflow/tfjs');
const nsfw = require('nsfwjs');
const fs = require('fs');

let nsfwModel;

// Das Modell beim Serverstart laden
async function loadModerationModel() {
    console.log("Lade Jugendschutz-Modell...");
    nsfwModel = await nsfw.load();
    console.log("Modell bereit!");
}
loadModerationModel();

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

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

const express = require('express');
const http = require('http'); // Neu: HTTP-Modul laden
const { Server } = require('socket.io'); // Neu: Socket.io laden

const app = express();
const server = http.createServer(app); // Den Express-Server in einen HTTP-Server "einwickeln"

const io = new Server(server, {
    cors: {
        origin: "*", // Erlaubt Zugriff von deinem Frontend
        methods: ["GET", "POST"]
    }
});

// Socket.io Logik: Wenn ein Nutzer online kommt
io.on('connection', (socket) => {
    console.log('Ein Nutzer ist verbunden:', socket.id);

    // Nutzer einem "Raum" mit seinem Usernamen zuweisen
    socket.on('join', (username) => {
        socket.join(username);
        console.log(`${username} ist bereit für Anrufe.`);
    });

    // Signal für einen Anruf weiterleiten
    socket.on('call-user', (data) => {
        // data enthält: { to: 'Empfänger', offer: 'Verbindungsdaten', from: 'Absender' }
        io.to(data.to).emit('incoming-call', {
            from: data.from,
            offer: data.offer
        });
    });

    socket.on('disconnect', () => {
        console.log('Nutzer getrennt');
    });
});

// WICHTIG: Am Ende der Datei nicht mehr app.listen, sondern server.listen nutzen!
server.listen(3000, () => {
    console.log('Server läuft auf Port 3000 inkl. Socket.io');
});
const port = process.env.PORT || 3000;

// MIDDLEWARE
// Erlaube nur bekannte Frontend-Origins (Vercel + lokale Entwicklung)
const allowedOrigins = [
    'https://safespeak-frontend-web.vercel.app', // Vercel-Frontend
    'http://localhost:3000',                    // Lokale Entwicklung (z.B. React/Node)
    'http://localhost:5173',                    // Optional: Vite/dev-Server
];

app.use(cors({
    origin(origin, callback) {
        // Ohne Origin (z.B. Curl/Postman) ebenfalls erlauben
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`Not allowed by CORS: ${origin}`));
        }
    },
    // Exponiere Content-Disposition, damit Downloads funktionieren
    exposedHeaders: ['Content-Disposition'],
}));

app.use(express.json());

// SICHERE DATEI-DOWNLOAD ROUTE
app.get('/download/:filePath', verifyToken, (req, res) => {
    // 1. Nur den Dateinamen extrahieren, um Pfad-Manipulationen (../) zu verhindern
    const fileName = path.basename(req.params.filePath);
    const absolutePath = path.join(__dirname, 'uploads', fileName);
    
    const clientUsername = req.user.username; 
    
    getUserId(clientUsername, (err, clientId) => {
        if (err || !clientId) {
            logger.error(`Kritischer Fehler: Download-Client ${clientUsername} nicht in DB.`);
            return res.status(500).json({ error: 'Interner Autorisierungsfehler.' });
        }
        
        // 2. Datenbank-Check: Darf dieser User die Datei sehen?
        // Wir suchen nach einer Nachricht, die diesen Dateipfad hat UND wo der User Sender oder Empfänger ist.
        db.get(`
            SELECT * FROM messages 
            WHERE file_path LIKE ? AND (sender_id = ? OR receiver_id = ?)
        `, [`%${fileName}%`, clientId, clientId], (err, row) => {
            if (err) {
                logger.error(`Datenbankfehler bei Download-Prüfung: ${err.message}`);
                return res.status(500).json({ error: 'Interner Serverfehler.' });
            }
            
            if (!row) {
                logger.warn(`Zugriff verweigert: ${clientUsername} wollte ${fileName} laden.`);
                return res.status(403).json({ error: 'Zugriff verweigert oder Datei nicht gefunden.' });
            }

            // 3. Datei senden
            res.download(absolutePath, fileName, (err) => {
                if (err) {
                    if (res.headersSent) {
                        // Header wurden bereits gesendet, wir können keine JSON-Fehlermeldung mehr schicken
                        return;
                    }
                    logger.error(`Fehler beim Dateidownload: ${err}`);
                    res.status(404).json({ error: 'Datei auf dem Server nicht gefunden.' }); 
                } else {
                    logger.info(`Download erfolgreich: ${fileName} durch ${clientUsername}.`);
                }
            });
        });
    });
});

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
        // Tabelle 'users' erstellen
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                location TEXT
            )
        `, (err) => {
            if (err) {
                logger.error(`Fehler beim Erstellen der Tabelle 'users': ${err.message}`);
            } else {
                logger.info("Tabelle 'users' ist bereit.");
            }
        });

        // Tabelle 'messages' erstellen
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
// Liste verbotener Begriffe und Muster (Erweiterbar)
const blockList = [
    /selbstmord/i, /suizid/i, /umbringen/i, 
    /nacktbild/i, /porno/i, /sex/i, /nude/i
];

function isContentBlocked(text) {
    if (!text) return false;
    // Prüft, ob einer der Begriffe im Text vorkommt
    return blockList.some(pattern => pattern.test(text));
}

// ---------------------------------
// ROUTEN
// ---------------------------------

// Benutzer registrieren
// Benutzer registrieren
app.post('/register', 
    [
        body('username')
            .isString().withMessage('Benutzername muss ein Text sein.')
            .isLength({ min: 3 }).withMessage('Benutzername muss mindestens 3 Zeichen lang sein.')
            .matches(/^[a-zA-Z0-9_]+$/).withMessage('Benutzername darf nur Buchstaben, Zahlen und Unterstriche enthalten.')
            .trim().escape(), 
        body('password')
            .isLength({ min: 8 }).withMessage('Passwort muss mindestens 8 Zeichen lang sein.'),
        body('location').trim().escape() // Location validieren
    ],
    async (req, res) => { 
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn(`Registrierung abgelehnt. Validierungsfehler: ${errors.array()[0].msg}`);
            return res.status(400).json({ error: errors.array()[0].msg });
        }
        
        const { username, password, location } = req.body;

        try {
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            db.get(`SELECT id FROM users WHERE username = ? AND location = ? AND is_blocked = 1`, 
                [username, location], (err, row) => {
                if (row) {
                    return res.status(403).json({ error: "Dieser Name an diesem Standort ist dauerhaft vom System ausgeschlossen." });
                }
                // ... restliche Registrierung
            });

            db.run(
                "INSERT INTO users (username, password, location) VALUES (?, ?, ?)", 
                [username, hashedPassword, location || null], 
                function(err) {
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
                }
            );

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

    db.get(`SELECT is_blocked FROM users WHERE username = ?`, [username], (err, row) => {
        if (row && row.is_blocked) {
            return res.status(403).json({ error: "Dieser Account ist permanent gesperrt." });
        }
        // ... restlicher Login
    });
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


        app.post('/send', verifyToken, upload.single('file'), async (req, res) => {
            const { receiverUsername, content } = req.body;
            const senderUsername = req.user.username;

            // 1. Text-Filter (Suizid/Gewalt)
            if (isContentBlocked(content)) {
                if (req.file) fs.unlinkSync(req.file.path); // Datei löschen, falls vorhanden
                return res.status(400).json({ error: "Nachricht blockiert (Sicherheitsrichtlinien)." });
            }

            // 2. Bild-Filter (Sexualsperre)
            if (req.file) {
                try {
                    const imageBuffer = fs.readFileSync(req.file.path);
                    // Das Bild für die KI vorbereiten
                    const image = tf.node.decodeImage(imageBuffer, 3);
                    const predictions = await nsfwModel.classify(image);
                    image.dispose(); // Speicher wieder freigeben

                    // Wir prüfen auf 'Porn' oder 'Hentai' mit einer Wahrscheinlichkeit > 60%
                    const isUnsafe = predictions.some(p => 
                        (p.className === 'Porn' || p.className === 'Hentai') && p.probability > 0.6
                    );

                    if (isUnsafe) {
                        fs.unlinkSync(req.file.path); // Beweis vernichten ;)
                        return res.status(400).json({ error: "Bild blockiert: Unzulässiger Inhalt erkannt." });
                    }
                } catch (err) {
                    console.error("Fehler bei Bildanalyse:", err);
                    // Im Zweifel: Datei löschen, wenn die Analyse fehlschlägt
                    fs.unlinkSync(req.file.path);
                    return res.status(500).json({ error: "Fehler bei der Sicherheitsprüfung des Bildes." });
                }
            }

            // ... Dein restlicher Code zum Speichern in der DB ...
        });

        const blockUser = () => {
            db.run(`UPDATE users SET strikes = strikes + 1 WHERE id = ?`, [req.user.id], (err) => {
                if (err) return console.error(err);

                // Aktuelle Strike-Zahl prüfen
                db.get(`SELECT strikes FROM users WHERE id = ?`, [req.user.id], (err, row) => {
                    if (row && row.strikes >= 3) {
                        const twoDaysLater = new Date();
                            twoDaysLater.setDate(twoDaysLater.getDate() + 2);

                            db.run(`UPDATE users SET is_blocked = 1, deletion_date = ? WHERE id = ?`, 
                                [twoDaysLater.toISOString(), req.user.id], () => {
                                console.log(`User ${req.user.username} wurde permanent gesperrt.`);
                            });
                        }
                    });
                });
            };

            // Aufruf der Funktion im Fehlerfall: 
            if (isContentBlocked(content) || isUnsafe) {
                if (req.file) fs.unlinkSync(req.file.path);
                blockUser(); // Strike hinzufügen / Sperre prüfen
                return res.status(403).json({ 
                    error: "Sicherheitsverstoß: Dein Account wurde aufgrund wiederholter Verstöße für 2 Tage gesperrt und wird danach unwiderruflich gelöscht." 
                });
            }

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



// Datei-Download (JETZT GESCHÜTZT UND KORREKT)
app.get('/download/:filePath', verifyToken, (req, res) => {
    // 1. Nur den Dateinamen extrahieren (Sicherheit gegen ../)
    const fileName = path.basename(req.params.filePath);
    const absolutePath = path.join(__dirname, 'uploads', fileName);
    
    const clientUsername = req.user.username; 
    
    getUserId(clientUsername, (err, clientId) => {
        if (err || !clientId) {
            logger.error(`Kritischer Fehler: Download-Client ${clientUsername} nicht in DB.`);
            return res.status(500).json({ error: 'Interner Autorisierungsfehler.' });
        }
        
        // 2. Datenbank-Check: Ist der User berechtigt?
        db.get(`
            SELECT * FROM messages 
            WHERE file_path LIKE ? AND (sender_id = ? OR receiver_id = ?)
        `, [`%${fileName}%`, clientId, clientId], (err, row) => {
            if (err) {
                logger.error(`Datenbankfehler bei Download-Prüfung: ${err.message}`);
                return res.status(500).json({ error: 'Interner Serverfehler.' });
            }
            
            if (!row) {
                logger.warn(`Zugriff verweigert: ${clientUsername} wollte ${fileName} laden.`);
                return res.status(403).json({ error: 'Zugriff verweigert oder Datei nicht gefunden.' });
            }

            // 3. Datei senden
            res.download(absolutePath, fileName, (err) => {
                if (err) {
                    if (!res.headersSent) {
                        logger.error(`Fehler beim Dateidownload: ${err}`);
                        res.status(404).json({ error: 'Datei nicht gefunden.' }); 
                    }
                } else {
                    logger.info(`Download erfolgreich: ${fileName} durch ${clientUsername}.`);
                }
            });
        });
    });
});

app.get('/contacts', verifyToken, (req, res) => {
    const userId = req.user.userId;

    // Findet Leute am selben Ort ODER Leute, mit denen man schon geschrieben hat
    const sql = `
        SELECT DISTINCT id, username, location FROM users 
        WHERE id != ? AND (
            (location IS NOT NULL AND location = (SELECT location FROM users WHERE id = ?))
            OR id IN (SELECT receiver_id FROM messages WHERE sender_id = ?)
            OR id IN (SELECT sender_id FROM messages WHERE receiver_id = ?)
        )
    `;

    db.all(sql, [userId, userId, userId, userId], (err, rows) => {
        if (err) {
            logger.error(`Fehler beim Laden der Kontakte: ${err.message}`);
            return res.status(500).json({ error: "Fehler beim Laden der Kontakte." });
        }
        res.json(rows);
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

// Einmal pro Stunde alle abgelaufenen Accounts "reinigen"
setInterval(() => {
    const now = new Date().toISOString();
    // Lösche Nachrichten und sensible Daten, aber behalte den User-Eintrag (ID, Name, Ort, is_blocked)
    db.run(`UPDATE users SET password = 'DELETED', deletion_date = NULL WHERE is_blocked = 1 AND deletion_date <= ?`, [now]);
    console.log("Bereinigung gesperrter Accounts durchgeführt.");
}, 1000 * 60 * 60); // Alle 60 Minuten

app.listen(port, () => {
    logger.info(`Server läuft auf Port ${port}`); // KORREKTUR: logger.info
});