const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
require('dotenv').config();

// --- استيراد الملفات المرفوعة بجانب السيرفر مباشرة ---
const { validateMovie, validateActor } = require('./validate'); // تم التأكد من المسار
const auditLog = require('./audit'); 
const errorHandler = require('./errorHandler');

const app = express();

// إعداد مهم لـ Vercel لكي يعمل الـ Rate Limit بشكل صحيح
app.set('trust proxy', 1);

const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error('[CRITICAL] JWT_SECRET is missing!');
    process.exit(1);
}

// --- CONFIGURATION & SECURITY ---
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',') 
    : ['https://rafiq-backend1.vercel.app', 'electron://rafiq'];

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "https:", "data:"],
            connectSrc: ["'self'", "https://*.supabase.co"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }
}));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

app.use(morgan('combined'));
app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1 || process.env.NODE_ENV === 'development') {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '5mb' }));

// --- RATE LIMITERS ---
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Rate limit exceeded.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many login attempts.' }
});

app.use(limiter);

// --- SUPABASE CLIENT ---
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
const supabase = (supabaseUrl && supabaseKey) ? createClient(supabaseUrl, supabaseKey) : null;

// --- MYSQL POOL ---
let pool;
if (process.env.DB_HOST && process.env.DB_USER && process.env.DB_NAME) {
    pool = mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10
    });
}

// --- AUTH MIDDLEWARE ---
const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, { issuer: 'rafiq-secure-api' }, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Access denied' });
        req.admin = decoded;
        next();
    });
};

// --- AUTH ROUTES ---
app.post('/api/admin/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Credentials required' });

    try {
        if (!supabase) return res.status(500).json({ error: 'Database service unavailable' });
        
        const { data: admin, error } = await supabase
            .from('admins')
            .select('id, username, password')
            .eq('username', username.toLowerCase().trim())
            .single();
        
        if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });

        const isValid = await bcrypt.compare(password, admin.password);
        if (!isValid) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign(
            { id: admin.id, username: admin.username, role: 'admin' }, 
            JWT_SECRET, 
            { expiresIn: '24h', issuer: 'rafiq-secure-api', subject: String(admin.id) }
        );

        res.json({ token, message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Helper Map
const mapMovie = (m) => ({
    ...m,
    releaseDate: m.release_date || m.releasedate || m.releaseDate || '',
    trailerUrl: m.trailer_url || m.trailerurl || m.trailerUrl || '',
    watchUrls: m.movie_servers || [],
    actors: (m.movie_actors || []).map(a => a.actor_id)
});

const mapSeries = (s) => ({
    ...s,
    releaseDate: s.release_date || s.releasedate || s.releaseDate || '',
    trailerUrl: s.trailer_url || s.trailerurl || s.trailerUrl || '',
    actors: (s.series_actors || []).map(a => a.actor_id),
    seasons: (s.seasons || []).map(sea => ({
        ...sea,
        episodes: (sea.episodes || []).map(e => ({
            ...e,
            number: e.episode_number || e.episodenumber || e.episodeNumber || 0,
            watchUrls: e.episode_servers || []
        })).sort((a,b) => a.number - b.number)
    })).sort((a,b) => a.number - b.number)
});

// --- PUBLIC ROUTES ---
app.get('/api/public/movies', async (req, res) => {
    try {
        const { data, error } = await supabase.from('movies').select('*, movie_servers(name, url), movie_actors(actor_id)').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data ? data.map(mapMovie) : []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/public/movies/:id', async (req, res) => {
    try {
        const { data, error } = await supabase.from('movies').select('*, movie_servers(name, url), movie_actors(actor_id)').eq('id', req.params.id).single();
        if (error) throw error;
        res.json(mapMovie(data));
    } catch (error) { res.status(404).json({ error: 'Movie not found' }); }
});

app.get('/api/public/series', async (req, res) => {
    try {
        const { data, error } = await supabase.from('series').select('*, series_actors(actor_id)').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data ? data.map(s => ({
            ...s,
            releaseDate: s.release_date || s.releasedate || s.releaseDate || '',
            actors: (s.series_actors || []).map(a => a.actor_id)
        })) : []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/public/series/:id', async (req, res) => {
    try {
        const { data, error } = await supabase.from('series').select('*, series_actors(actor_id), seasons(*, episodes(*, episode_servers(name, url)))').eq('id', req.params.id).single();
        if (error) throw error;
        res.json(mapSeries(data));
    } catch (error) { res.status(404).json({ error: 'Series not found' }); }
});

app.get('/api/public/actors', async (req, res) => {
    try {
        const { data, error } = await supabase.from('actors').select('*').order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data || []);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- PROTECTED ADMIN ROUTES ---
app.post('/api/admin/movies', authenticate, validateMovie, auditLog('SAVE_MOVIE'), async (req, res) => {
    try {
        const { actors, watchUrls, ...rawMovie } = req.body;
        const dbMovie = {
            id: rawMovie.id,
            title: rawMovie.title,
            description: rawMovie.description,
            rating: rawMovie.rating,
            release_date: rawMovie.releaseDate,
            image: rawMovie.image,
            background: rawMovie.background,
            trailer_url: rawMovie.trailerUrl
        };
        const { error } = await supabase.from('movies').upsert(dbMovie);
        if (error) throw error;

        if (actors !== undefined) {
            await supabase.from('movie_actors').delete().eq('movie_id', dbMovie.id);
            if (actors.length) await supabase.from('movie_actors').insert(actors.map(aid => ({ movie_id: dbMovie.id, actor_id: aid })));
        }

        if (watchUrls !== undefined) {
            await supabase.from('movie_servers').delete().eq('movie_id', dbMovie.id);
            if (watchUrls.length) await supabase.from('movie_servers').insert(watchUrls.map(s => ({ movie_id: dbMovie.id, name: s.name, url: s.url })));
        }

        res.json({ message: 'Movie saved successfully', id: dbMovie.id });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/admin/movies/:id', authenticate, auditLog('DELETE_MOVIE'), async (req, res) => {
    try {
        const { error } = await supabase.from('movies').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ message: 'Movie deleted' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/admin/actors', authenticate, validateActor, auditLog('SAVE_ACTOR'), async (req, res) => {
    try {
        const { id, name, image } = req.body;
        const { error } = await supabase.from('actors').upsert({ id, name, image });
        if (error) throw error;
        res.json({ message: 'Actor saved' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/admin/actors/:id', authenticate, auditLog('DELETE_ACTOR'), async (req, res) => {
    try {
        const { error } = await supabase.from('actors').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ message: 'Actor deleted' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.get('/', (req, res) => res.send('Rafiq Secure Backend is running 🚀'));

// Export for Vercel
app.use(errorHandler);
module.exports = app;
