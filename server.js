import 'dotenv/config';
import bcrypt from 'bcrypt';
import express from 'express';
import sqlite3v from 'sqlite3';
import multer from 'multer';
import path from 'path';

import cors from 'cors';




import jwt from 'jsonwebtoken'; 
import winston, { format } from 'winston';
import { Server } from 'socket.io';
import http from 'http';
import fs from 'fs';
import { fileURLToPath } from 'url';


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { combine, timestamp, printf, colorize } = format;

// --- LOGGER ---
const logFormat = printf(({ level, message, timestamp }) => `${timestamp} [${level}]: ${message}`);
const logger = winston.createLogger({
    level: 'info',
    format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), logFormat),
    transports: [
        new winston.transports.Console({ format: combine(colorize(), logFormat) }),

    ]
});



const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { 
        origin: ["https://safespeak-frontend-web.vercel.app", "http://localhost:5173"],
        methods: ["GET", "POST"] 
    }
});

const JWT_SECRET = process.env.JWT_SECRET || 'dein_super_geheimnis';
const saltRounds = 10;
const port = process.env.PORT || 3000;

// --- UPLOADS ORDNER PRÜFEN ---
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage: storage });

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(uploadDir));

// --- DB INITIALISIERUNG ---
const db = new sqlite3v.Database('safespeak.db');
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, street TEXT, zip TEXT, city TEXT, location TEXT, is_blocked INTEGER DEFAULT 0, strikes INTEGER DEFAULT 0, deletion_date TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, content TEXT, file_path TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
});

// --- AUTH MIDDLEWARE ---
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Nicht autorisiert' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token ungültig' });
        req.user = user;
        next();
    });
}

// --- ROUTEN ---

app.post('/register', async (req, res) => {
    const { username, password, street, zip, city } = req.body;
    const location = `${street}, ${zip} ${city}`; // Für die Umkreissuche
    const hashed = await bcrypt.hash(password, saltRounds);
    
    db.run("INSERT INTO users (username, password, street, zip, city, location) VALUES (?, ?, ?, ?, ?, ?)", 
    [username, hashed, street, zip, city, location], function(err) {
        if (err) return res.status(400).json({ error: "Username existiert bereits" });
        res.json({ message: "Erfolg!", userId: this.lastID });
    });
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: "Daten falsch" });
        }
        const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, username: user.username });
    });
});


app.get('/contacts', verifyToken, (req, res) => {
    db.get("SELECT location FROM users WHERE id = ?", [req.user.userId], (err, user) => {
        const myZip = user?.location?.substring(0, 5) || "";
        db.all("SELECT id, username, location FROM users WHERE id != ? AND location LIKE ?", [req.user.userId, `${myZip}%`], (err, rows) => {
            res.json(rows || []);
        });
    });
});

app.get('/messages', verifyToken, (req, res) => {
    const { withUser } = req.query;
    db.all(`SELECT m.*, u1.username as sender, u2.username as receiver 
            FROM messages m 
            JOIN users u1 ON m.sender_id = u1.id 
            JOIN users u2 ON m.receiver_id = u2.id
            WHERE (u1.username = ? AND u2.username = ?) OR (u1.username = ? AND u2.username = ?)
            ORDER BY timestamp ASC`, [req.user.username, withUser, withUser, req.user.username], (err, rows) => {
        res.json(rows || []);
    });
});

io.on('connection', (socket) => {
    socket.on('join', (username) => {
        socket.join(username);
        console.log(`${username} ist dem Chat beigetreten`);
    });

    socket.on('private_message', ({ to, content, token }) => {
        // Hier validiert der Server den Token und speichert in die DB
        jwt.verify(token, JWT_SECRET, (err, decoded) => {
            if (err) return;
            const sender = decoded.username;
            
            // In DB speichern
            db.run("INSERT INTO messages (sender_id, receiver_id, content) SELECT u1.id, u2.id, ? FROM users u1, users u2 WHERE u1.username = ? AND u2.username = ?", [content, sender, to]);
            
            // An Empfänger senden
            io.to(to).emit('new_message', { sender, content });
        });
    });
});

server.listen(port, () => {
    console.log(`Server läuft auf Port ${port}`);
});