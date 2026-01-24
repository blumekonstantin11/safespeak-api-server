import 'dotenv/config';
import bcrypt from 'bcrypt';
import express from 'express';
import sqlite3v from 'sqlite3';
import multer from 'multer';
import path from 'path';
import { body, validationResult } from 'express-validator';
import cors from 'cors';

import rateLimit from 'express-rate-limit';


import jwt from 'jsonwebtoken'; 
import winston, { format } from 'winston';
import { Server } from 'socket.io';
import http from 'http';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Hilfsvariablen für Pfade (da ES-Module)
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { combine, timestamp, printf, colorize } = format;

// --- LOGGER KONFIGURATION ---
const logFormat = printf(({ level, message, timestamp }) => `${timestamp} [${level}]: ${message}`);
const logger = winston.createLogger({
    level: 'info',
    format: combine(timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }), logFormat),
    transports: [
        new winston.transports.Console({ format: combine(colorize(), logFormat) }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});



const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: "*", methods: ["GET", "POST"] }
});

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_123';
const saltRounds = 10;
const port = process.env.PORT || 3000;

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// --- DATENBANK ---
const db = new sqlite3v.Database('safespeak.db', (err) => {
    if (err) logger.error('DB Fehler: ' + err.message);
    else {
        logger.info('DB verbunden.');
        initializeDB();
    }
});

function initializeDB() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, location TEXT, is_blocked INTEGER DEFAULT 0, strikes INTEGER DEFAULT 0, deletion_date TEXT)`);
        db.run(`CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, content TEXT, file_path TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    });
}

// --- HELFER & AUTH ---
function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token fehlt' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token ungültig' });
        req.user = user;
        next();
    });
}

// --- ROUTEN ---

// Login
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
        if (err || !user) return res.status(401).json({ error: "Nutzer nicht gefunden" });
        if (user.is_blocked) return res.status(403).json({ error: "Account gesperrt" });
        
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ userId: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ token, username: user.username });
        } else {
            res.status(401).json({ error: "Passwort falsch" });
        }
    });
});

// Registrierung
app.post('/register', async (req, res) => {
    const { username, password, location } = req.body;
    const hashed = await bcrypt.hash(password, saltRounds);
    db.run("INSERT INTO users (username, password, location) VALUES (?, ?, ?)", [username, hashed, location], function(err) {
        if (err) return res.status(400).json({ error: "Username existiert bereits" });
        res.json({ message: "Erfolg!", userId: this.lastID });
    });
});

// KONTAKTE MIT PLZ-FILTER (Hier ist die neue Logik!)
app.get('/contacts', verifyToken, (req, res) => {
    db.get("SELECT location FROM users WHERE id = ?", [req.user.userId], (err, user) => {
        if (err || !user) return res.status(500).json({ error: "User-Location nicht gefunden" });

        // Wir nehmen die ersten 5 Zeichen der Location (PLZ)
        const myZip = user.location ? user.location.substring(0, 5) : "";

        // Suche alle User außer mir selbst, die mit derselben PLZ anfangen
        db.all("SELECT id, username, location FROM users WHERE id != ? AND location LIKE ?", [req.user.userId, `${myZip}%`], (err, rows) => {
            if (err) return res.status(500).json({ error: "Fehler beim Laden" });
            res.json(rows);
        });
    });
});

// --- SOCKET.IO ---
io.on('connection', (socket) => {
    logger.info('Socket verbunden: ' + socket.id);
    socket.on('join', (username) => socket.join(username));
    socket.on('disconnect', () => logger.info('Socket getrennt'));
});

// --- SERVER START (Nur einmal!) ---
server.listen(port, () => {
    logger.info(`SafeSpeak Server bereit auf Port ${port}`);
});