import bcrypt from 'bcrypt';
import express from 'express';
import sqlite3v from 'sqlite3'; // Wir importieren sqlite3 als 'sqlite3v' (für verbose)
import multer from 'multer';
import path from 'path';

const saltRounds = 10; // Empfohlene Anzahl der Runden für das Hashing
// server.js (ganz oben, zu den anderen Imports)
// NEU: Importiere die notwendigen Funktionen von express-validator
import { body, validationResult } from 'express-validator';

import cors from 'cors'; 

// NEU: Imports und Konfiguration für den Winston Logger
const winston = require('winston');
const { combine, timestamp, printf, colorize } = winston.format;

// NEU: Definiere das Format für die Log-Einträge
const logFormat = printf(({ level, message, timestamp }) => {
  return `${timestamp} [${level}]: ${message}`;
});

// NEU: Erstelle den Logger
const logger = winston.createLogger({
  level: 'info',
  format: combine(
    timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    logFormat
  ),
  transports: [
    // 1. Konsole: Zeigt farbige Logs beim Entwickeln
    new winston.transports.Console({
      format: combine(
        colorize(), 
        logFormat
      )
    }),
    
    // 2. Datei: Speichert alle Logs auf dem Server (combined.log)
    new winston.transports.File({ filename: 'combined.log' }),
    
    // 3. Datei: Speichert nur Fehler (error.log)
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
  ],
  exitOnError: false, 
});

const app = express();

//..

// Fügen Sie DIESE ZEILE HINZU, um CORS für alle Anfragen zu aktivieren
app.use(cors()); 

// ... der Rest Ihrer app.use(express.json()) Zeilen ...
const port = process.env.PORT || 3000;

app.use(express.json());
// app.use(express.static('.')); // DIESE ZEILE WURDE ZUR SICHERHEIT ENTFERNT/AUSKOMMENTIERT

// Konfiguration für Multer (Dateispeicherort)
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/'); // Alle Dateien im 'uploads' Ordner speichern
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Dateiname mit Zeitstempel
    }
});
const upload = multer({ storage: storage });

// Nur die Klasse importieren und direkt verwenden
const db = new sqlite3v.Database('safespeak.db', (err) => {
    if (err) {
        console.error('Fehler beim Verbinden mit der Datenbank:', err.message);
        // ... im else-Block der Datenbankverbindung
    } else {
        console.log('Erfolgreich mit der SafeSpeak-Datenbank verbunden.');
        // HIER MUSS DIE INITIALISIERUNG AUFGERUFEN WERDEN!
        initialize(); // RUFEN SIE DIE FUNKTION AUF, WENN SIE NOCH NICHT DA IST!
    }
});

function initialize() {
    db.serialize(() => { // DIESER BLOCK IST NUN SEHR WICHTIG
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
        `);
        // ... Code für die messages Tabelle hier ...
        console.log("Datenbanktabellen wurden überprüft und erstellt.");
    });
}
// Neue Tabellen für Dateiinhalte und Dateinachrichten erstellen
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        );
    `);
    db.run(`
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            content TEXT,
            file_path TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );
    `);
    console.log('Datenbanktabellen wurden überprüft und erstellt.');
});

// Funktion, um die Benutzer-ID anhand des Benutzernamens zu finden
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

// Benutzer registrieren
app.post('/register', 
    // NEU: Validierungs-Middleware
    [
        // Prüft, ob der Username existiert und nur Buchstaben/Zahlen/Unterstriche enthält (Sanitization)
        body('username')
            .isString().withMessage('Benutzername muss ein Text sein.')
            .isLength({ min: 3 }).withMessage('Benutzername muss mindestens 3 Zeichen lang sein.')
            .matches(/^[a-zA-Z0-9_]+$/).withMessage('Benutzername darf nur Buchstaben, Zahlen und Unterstriche enthalten.')
            .trim() // Entfernt Leerzeichen am Anfang und Ende (Sanitization)
            .escape(), // Kodiert HTML-Entitäten (Sanitization)

        // Prüft die Passwort-Regeln
        body('password')
            .isLength({ min: 8 }).withMessage('Passwort muss mindestens 8 Zeichen lang sein.')
    ],
    // Hier startet die eigentliche Logik des Routes
    async (req, res) => { 
    
        // NEU: Ergebnis der Validierung prüfen
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn(`Registrierung abgelehnt. Validierungsfehler: ${errors.array()[0].msg} für Benutzername: ${req.body.username}`);
            // Sende den ersten Fehler im Array zurück
            return res.status(400).json({ errors: errors.array({ onlyFirstError: true })[0].msg });
        }
        
        const { username, password } = req.body;
        // ... der Rest deines Codes folgt hier
        }
    )

// Benutzer anmelden
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // 1. Gespeicherten Hash für den Benutzer abrufen
    db.get("SELECT id, password FROM users WHERE username = ?", [username], async (err, row) => {
        if (err || !row) {
            // Gibt generische Fehlermeldung aus Sicherheitsgründen zurück
            return res.status(401).json({ error: "Anmeldung fehlgeschlagen. Ungültiger Benutzername oder Passwort." });
        }

        const storedHash = row.password;

        try {
            // 2. Eingegebenes Passwort mit dem gespeicherten Hash vergleichen
            const match = await bcrypt.compare(password, storedHash);

            if (match) {
                res.json({ message: "Anmeldung erfolgreich!", userId: row.id });
            } else {
                // Wenn der Hash nicht übereinstimmt
                res.status(401).json({ error: "Anmeldung fehlgeschlagen. Ungültiger Benutzername oder Passwort." });
            }
        } catch (compareError) {
            console.error("Fehler beim Vergleich:", compareError);
            res.status(500).json({ error: "Ein interner Fehler ist aufgetreten." });
        }
    });
});

// Angepasste Route zum Senden von Nachrichten und Dateien
app.post('/send', 
    upload.single('file'), 
    // NEU: Validierungs-Middleware
    [
        body('senderUsername').trim().escape(),
        body('receiverUsername').trim().escape(),
        body('content')
            .optional() // Inhalt ist optional, da es auch nur eine Datei sein kann
            .isLength({ max: 2000 }).withMessage('Nachricht ist zu lang (max. 2000 Zeichen).')
            .escape() // Bereinigt den Nachrichteninhalt
    ],
    // Hier startet die eigentliche Logik des Routes
    (req, res) => {
        
        // NEU: Ergebnis der Validierung prüfen
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            logger.warn(`Senden abgelehnt. Validierungsfehler: ${errors.array()[0].msg}.`);
            return res.status(400).json({ errors: errors.array({ onlyFirstError: true })[0].msg });
        }
        
        // ... der Rest deines Codes folgt hier
        });

// NEUE, GESCHÜTZTE ROUTE FÜR DATEI-DOWNLOADS
app.get('/download/:filePath', (req, res) => {
    // Der Dateipfad wird als 'uploads/DATEINAME.EXT' übergeben, 
    // aber wir müssen ihn wieder zusammensetzen, da Express alles nach dem / als Parameter sieht
    const requestedPath = req.params.filePath; 
    
    // Annahme: Der Client schickt den Absender-Username im Query-Parameter
    // Dies ist eine notwendige PRÜFUNG, um sicherzustellen, dass nur Berechtigte herunterladen
    const clientUsername = req.query.username; 
    
    if (!clientUsername) {
        return res.status(401).json({ error: 'Autorisierung fehlt.' });
    }

    // 1. Hole die Benutzer-ID des anfragenden Clients
    getUserId(clientUsername, (err, clientId) => {
        if (err || !clientId) {
            return res.status(404).json({ error: 'Benutzer nicht gefunden.' });
        }
        
        // 2. Prüfe in der 'messages'-Tabelle, ob diese Datei
        //    zwischen dem Client und einem Partner existiert.
        //    (Der Client muss entweder Absender oder Empfänger sein)
        db.get(`
            SELECT * FROM messages 
            WHERE file_path = ? AND (sender_id = ? OR receiver_id = ?)
        `, [requestedPath, clientId, clientId], (err, row) => {
            if (err || !row) {
                // Wenn kein Eintrag gefunden wird, ist der Zugriff verweigert
                return res.status(403).json({ error: 'Zugriff verweigert oder Datei nicht gefunden.' });
            }

            // 3. Wenn die Überprüfung erfolgreich war: Datei senden!
            const absolutePath = path.resolve(requestedPath);
            res.download(absolutePath, (err) => {
                if (err) {
                    console.error('Fehler beim Dateidownload:', err);
                    // Sende einen Fehlercode, aber verringere das Risiko, den Pfad preiszugeben
                    res.status(500).json({ error: 'Fehler beim Laden der Datei.' }); 
                }
            });
        });
    });
});

// Angepasste Route zum Abrufen von Nachrichten und Dateien
app.get('/messages', (req, res) => {
    const { user1, user2 } = req.query;

    getUserId(user1, (err, user1Id) => {
        if (err) {
            return res.status(404).send({ message: `Benutzer '${user1}' nicht gefunden.` });
        }
        getUserId(user2, (err, user2Id) => {
            if (err) {
                return res.status(404).send({ message: `Benutzer '${user2}' nicht gefunden.` });
            }
            db.all(`
                SELECT * FROM messages 
                WHERE (sender_id = ? AND receiver_id = ?) 
                   OR (sender_id = ? AND receiver_id = ?) 
                ORDER BY timestamp ASC
            `, [user1Id, user2Id, user2Id, user1Id], (err, rows) => {
                if (err) {
                    return res.status(500).send({ message: 'Fehler beim Abrufen der Nachrichten.' });
                }
                res.status(200).json(rows);
            });
        });
    });
});

app.get('/', (req, res) => {
    res.send('Willkommen auf dem SafeSpeak-Server! Die Datenbank ist eingerichtet.');
});

// DIESEN BLOCK STATTDESSEN EINFÜGEN!
app.listen(port, () => {
    console.log(`Server läuft auf Port ${port}`);
});