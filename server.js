const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 1);

// DATABASE CONNECTION
mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log('✅ ZENOX DB CONNECTED');
    createDefaultAdmin();
})
.catch(err => console.log('❌ DB ERROR:', err.message));

// USER SCHEMA
const UserSchema = new mongoose.Schema({
    deviceId: { type: String, unique: true, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

// CREATE DEFAULT ADMIN
async function createDefaultAdmin() {
    try {
        const adminExists = await User.findOne({ role: 'admin' });
        if (!adminExists) {
            const adminPassword = process.env.ADMIN_PASSWORD || 'ZENOX@2026#SECURE$';
            const hashedPassword = await bcrypt.hash(adminPassword, 12);
            const admin = new User({
                deviceId: 'ZENOX-ADMIN-001',
                passwordHash: hashedPassword,
                role: 'admin'
            });
            await admin.save();
            console.log('✅ DEFAULT ADMIN CREATED');
        }
    } catch (error) {
        console.log('⚠️ ADMIN ERROR:', error.message);
    }
}

app.use(helmet());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));

app.use(session({
    secret: process.env.SESSION_SECRET,
    store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI, collectionName: 'sessions' }),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 },
    name: '__Secure-zenox-session'
}));

// CSRF TOKEN INITIATION
app.use((req, res, next) => {
    if (!req.session.token) {
        req.session.token = crypto.randomBytes(32).toString('hex');
    }
    res.locals.csrfToken = req.session.token;
    next();
});

// CSRF STRICT ENFORCEMENT
app.use((req, res, next) => {
    if (req.method === 'POST') {
        const token = req.body._csrf || req.headers['x-csrf-token'];
        if (!token || token !== req.session.token) {
            return res.status(403).send('⛔ ACCESS DENIED: CSRF TOKEN INVALID');
        }
    }
    next();
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'TOO MANY ATTEMPTS. SYSTEM LOCKED.'
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// AUTHENTICATION MIDDLEWARES
function requireAuth(req, res, next) {
    if (!req.session || !req.session.userId) {
        return res.redirect('/ZENOX-GATEWAY-LOGIN');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (req.session.role !== 'admin') {
        return res.status(403).send('⛔ ACCESS DENIED');
    }
    next();
}

// ROUTES
app.get('/', (req, res) => res.redirect('/ZENOX-GATEWAY-LOGIN'));

app.get('/ZENOX-GATEWAY-LOGIN', (req, res) => {
    if (req.session && req.session.userId) {
        return res.redirect('/ZENOX-PORTAL-CORE-X92');
    }
    res.render('login', { error: null });
});

app.post('/ZENOX-GATEWAY-LOGIN', authLimiter, async (req, res) => {
    const { deviceId, password } = req.body;
    try {
        const user = await User.findOne({ deviceId });
        if (!user) {
            return res.render('login', { error: 'INVALID ACCESS PRIVILEGES.' });
        }

        const isValid = await bcrypt.compare(password, user.passwordHash);
        if (!isValid) {
            return res.render('login', { error: 'INVALID ACCESS KEY.' });
        }

        req.session.userId = user._id;
        req.session.role = user.role;
        req.session.deviceId = user.deviceId;

        res.redirect('/ZENOX-PORTAL-CORE-X92');
    } catch (error) {
        res.render('login', { error: 'SERVER ERROR.' });
    }
});

// HIDDEN PATH DASHBOARD
app.get('/ZENOX-PORTAL-CORE-X92', requireAuth, (req, res) => {
    res.render('dashboard', { deviceId: req.session.deviceId, role: req.session.role });
});

// HIDDEN PATH ADMIN CONTROL PANEL
app.get('/ZENOX-MAIN-TERMINAL-ROOT', requireAuth, requireAdmin, async (req, res) => {
    try {
        const allUsers = await User.find({}, 'deviceId role createdAt');
        res.render('admin', { deviceId: req.session.deviceId, users: allUsers });
    } catch (error) {
        res.status(500).send('SERVER ERROR');
    }
});

app.get('/ZENOX-TERMINATE', (req, res) => {
    req.session.destroy(() => res.redirect('/ZENOX-GATEWAY-LOGIN'));
});

app.use((req, res) => res.status(404).send('NOT FOUND'));

app.listen(PORT, () => console.log(`🛡️ SERVER RUNNING ON PORT ${PORT}`));
