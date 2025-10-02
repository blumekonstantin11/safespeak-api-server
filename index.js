const bcrypt =require('bcrypt');
const saltRounds = 10; // Empfohlene Anzahl der Runden für das Hashing

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer'); // Multer-Paket importieren
const path = require('path');

const cors = require('cors');
const app = express();

// Fügen Sie DIESE ZEILE HINZU, um CORS für alle Anfragen zu aktivieren
app.use(cors()); 

// ... der Rest Ihrer app.use(express.json()) Zeilen ...
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('.'));

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

const db = new sqlite3.Database('safespeak.db', (err) => {
    if (err) {
        return console.error(err.message);
    }
    console.log('Erfolgreich mit der SafeSpeak-Datenbank verbunden.');
});

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
app.post('/register', async (req, res) => { 
    const { username, password } = req.body;

    try {
        // Passwort hashen (verschlüsseln)
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], function(err) {
            if (err) {
                // Prüfen, ob der Fehler ein doppelter Username ist
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: "Registrierung fehlgeschlagen. Username existiert bereits." });
                }
                return res.status(500).json({ error: "Ein unbekannter Fehler ist aufgetreten." });
            }
            res.json({ message: "Benutzer erfolgreich registriert!", userId: this.lastID });
        });

    } catch (hashError) {
        console.error("Fehler beim Hashing:", hashError);
        res.status(500).json({ error: "Fehler beim Verarbeiten des Passworts." });
    }
});

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
app.post('/send', upload.single('file'), (req, res) => {
    const { senderUsername, receiverUsername, content } = req.body;
    const filePath = req.file ? req.file.path : null;

    getUserId(senderUsername, (err, senderId) => {
        if (err) {
            return res.status(404).send({ message: `Absender-Benutzername '${senderUsername}' nicht gefunden.` });
        }
        getUserId(receiverUsername, (err, receiverId) => {
            if (err) {
                return res.status(404).send({ message: `Empfänger-Benutzername '${receiverUsername}' nicht gefunden.` });
            }
            db.run(`INSERT INTO messages (sender_id, receiver_id, content, file_path) VALUES (?, ?, ?, ?)`, 
                   [senderId, receiverId, content, filePath], 
                   function(err) {
                if (err) {
                    return res.status(500).send({ message: 'Fehler beim Senden der Nachricht.' });
                }
                res.status(201).send({ message: 'Nachricht erfolgreich gesendet!', messageId: this.lastID });
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