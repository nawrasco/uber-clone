const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const pool = new Pool();

app.use(express.json());

// Middleware للتحقق من التوكن
const authenticateToken = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).json({ message: 'Access denied' });

    jwt.verify(token, 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
    const { username, password, role, phone } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
        'INSERT INTO users (username, password, role, phone) VALUES ($1, $2, $3, $4) RETURNING *',
        [username, hashedPassword, role, phone]
    );
    res.json(result.rows[0]);
});

// تسجيل الدخول
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) return res.status(400).json({ message: 'User not found' });

    const validPassword = await bcrypt.compare(password, result.rows[0].password);
    if (!validPassword) return res.status(400).json({ message: 'Invalid password' });

    const token = jwt.sign({ id: result.rows[0].id }, 'your-secret-key');
    res.json({ token });
});

server.listen(5000, () => {
    console.log('Server is running on port 5000');
});