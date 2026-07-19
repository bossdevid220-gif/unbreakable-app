const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

app.set('trust proxy', 1);

mongoose.connect(process.env.MONGODB_URI)
.then(() => {
    console.log('SERVER CONNECTED TO DATABASE');
})
.catch(err => console.log('DATABASE ERROR:', err.message));

const UserSchema = new mongoose.Schema({
    deviceId: { type: String, unique: true, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: 'user', enum: ['user', 'admin'] }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);

app.use(helmet({
    contentSecurityPolicy: false
}));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    message: 'TOO MANY ATTEMPTS. PLEASE TRY AGAIN LATER.'
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET || 'ZENOX_SUPER_SECRET_KEY_2026',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        ttl: 24 * 60 * 60
    }),
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/ZENOX-GATEWAY-LOGIN');
    }
    next();
}

function requireAdmin(req, res, next) {
    if (req.session.role !== 'admin') {
        return res.status(403).send('ACCESS DENIED');
    }
    next();
}

app.get('/', (req, res) => {
    res.redirect('/ZENOX-GATEWAY-LOGIN');
});

app.get('/ZENOX-GATEWAY-LOGIN', (req, res) => {
    res.render('login', { error: null });
});

app.post('/ZENOX-GATEWAY-LOGIN', authLimiter, async (req, res) => {
    const { deviceId, password } = req.body;
    
    if (!deviceId || deviceId.includes('GENERATING')) {
        return res.render('login', { error: 'DEVICE ID ERROR. PLEASE REFRESH.' });
    }

    try {
        const masterPassword = process.env.ADMIN_PASSWORD || 'ZENOX@2026#SECURE$';
        
        if (password === masterPassword) {
            let user = await User.findOne({ deviceId });
            
            if (!user) {
                const hashedPassword = await bcrypt.hash(password, 12);
                user = new User({
                    deviceId: deviceId,
                    passwordHash: hashedPassword,
                    role: 'admin'
                });
                await user.save();
            }

            req.session.userId = user._id;
            req.session.role = user.role;
            req.session.deviceId = user.deviceId;

            return res.redirect('/ZENOX-PORTAL-CORE-X92');
        } else {
            return res.render('login', { error: 'INVALID ACCESS LICENSE KEY.' });
        }
    } catch (error) {
        res.render('login', { error: 'SERVER SAFETY ERROR.' });
    }
});

app.get('/ZENOX-PORTAL-CORE-X92', requireAuth, (req, res) => {
    res.render('dashboard', { deviceId: req.session.deviceId, role: req.session.role });
});

app.get('/ZENOX-MAIN-TERMINAL-ROOT', requireAuth, requireAdmin, async (req, res) => {
    try {
        const allUsers = await User.find({}, 'deviceId role createdAt');
        res.render('admin', { deviceId: req.session.deviceId, users: allUsers });
    } catch (error) {
        res.status(500).send('SERVER ERROR');
    }
});

app.get('/ZENOX-TERMINATE', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/ZENOX-GATEWAY-LOGIN');
    });
});

app.use((req, res) => {
    res.status(404).send('PAGE NOT FOUND');
});

app.listen(PORT, () => {
    console.log(`SERVER RUNNING ON PORT ${PORT}`);
});
