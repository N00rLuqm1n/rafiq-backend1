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

// Middlewares
// Middlewares (Flat Structure)
const { validateMovie, validateActor } = require('./validate');
const auditLog = require('./audit');
const errorHandler = require('./errorHandler');

const app = express();
app.set('trust proxy', 1); // For Vercel rate limiting
const PORT = process.env.PORT || 5001;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    console.error('[CRITICAL] JWT_SECRET is not defined in environment variables.');
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
            console.warn(`[SECURITY] Blocked cross-origin request from: ${origin}`);
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
    message: { error: 'Rate limit exceeded. Try again later.' }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5, // Stricter for login
    message: { error: 'Too many login attempts. Blocked for 15 minutes.' }
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
        if (err) {
            console.warn('[AUTH] Token verification failed:', err.message);
            return res.status(403).json({ error: 'Access denied' });
        }
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
        
        // جلب بيانات الأدمن مع تجاهل حالة الأحرف لحل مشاكل الدخول
        const { data: admin, error } = await supabase
            .from('admins')
            .select('id, username, password')
            .ilike('username', username.trim()) 
            .single();
        
        if (error || !admin) {
            console.warn(`[AUTH] Login fail - User not found: ${username}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // اختبار كلمة السر: نجرب التشفير أولاً ثم النص العادي كخيار احتياطي
        let isValid = false;
        try {
            isValid = await bcrypt.compare(password, admin.password);
        } catch (e) {
            isValid = false;
        }

        if (!isValid && password === admin.password) {
            isValid = true;
            console.info(`[AUTH] Legacy plain-text login for: ${admin.username}`);
        }

        if (!isValid) {
            console.warn(`[AUTH] Login fail - Wrong password for: ${username}`);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        console.log(`[AUTH] Admin ${admin.username} logged in successfully from ${req.ip}`);
        const token = jwt.sign(
            { id: admin.id, username: admin.username, role: 'admin' }, 
            JWT_SECRET, 
            { expiresIn: '24h', issuer: 'rafiq-secure-api', subject: String(admin.id) }
        );

        res.json({ token, message: 'Welcome back, ' + admin.username });
    } catch (error) {
        console.error('[AUTH FATAL]', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- HELPERS ---
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

// Helper to sanitize object for DB (Snake Case per discovered schema)
const toDBMovie = (m) => ({
    id: m.id,
    title: m.title,
    description: m.description,
    rating: m.rating,
    release_date: m.releaseDate,
    image: m.image,
    background: m.background,
    trailer_url: m.trailerUrl
});

const toDBSeries = (s) => ({
    id: s.id,
    title: s.title,
    description: s.description,
    rating: s.rating,
    release_date: s.releaseDate,
    image: s.image,
    background: s.background,
    trailer_url: s.trailerUrl
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
    console.log('[ADMIN] Saving Movie:', req.body.title);
    try {
        const { actors, watchUrls, ...rawMovie } = req.body;
        const dbMovie = toDBMovie(rawMovie);
        
        const { error } = await supabase.from('movies').upsert(dbMovie);
        if (error) {
            console.error('[ADMIN ERROR] Movie Upsert Failed:', error.message);
            return res.status(400).json({ error: error.message });
        }

        if (actors !== undefined) {
            await supabase.from('movie_actors').delete().eq('movie_id', dbMovie.id);
            if (actors.length) {
                await supabase.from('movie_actors').insert(actors.map(aid => ({ movie_id: dbMovie.id, actor_id: aid })));
            }
        }

        if (watchUrls !== undefined) {
            await supabase.from('movie_servers').delete().eq('movie_id', dbMovie.id);
            if (watchUrls.length) {
                await supabase.from('movie_servers').insert(watchUrls.map(s => ({ movie_id: dbMovie.id, name: s.name, url: s.url })));
            }
        }

        console.log('[ADMIN SUCCESS] Movie Saved Successfully');
        res.json({ message: 'Movie saved successfully', id: dbMovie.id });
    } catch (error) { 
        console.error('[ADMIN FATAL] Movie Save Error:', error);
        res.status(500).json({ error: error.message }); 
    }
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
    } catch (error) { 
        console.error('[ADMIN ERROR] Actor Save Failed:', error.message);
        res.status(400).json({ error: error.message }); 
    }
});

app.delete('/api/admin/actors/:id', authenticate, auditLog('DELETE_ACTOR'), async (req, res) => {
    try {
        const { error } = await supabase.from('actors').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ message: 'Actor deleted' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.post('/api/admin/series', authenticate, auditLog('SAVE_SERIES'), async (req, res) => {
    console.log('[ADMIN] Saving Series/Content:', req.body.title || 'Partial Update');
    try {
        const { actors, seasons, ...rawSeries } = req.body;
        const seriesId = rawSeries.id; // May be undefined for season-only updates

        if (!seriesId && !rawSeries.title && !seasons) {
             return res.status(400).json({ error: 'Invalid request: No ID or data provided' });
        }

        // Only upsert the main series row if metadata (like title) is provided
        if (rawSeries.title) {
            const dbSeries = {
                id: seriesId,
                title: rawSeries.title,
                description: rawSeries.description,
                rating: rawSeries.rating,
                release_date: rawSeries.release_date || rawSeries.releaseDate,
                image: rawSeries.image,
                background: rawSeries.background,
                trailer_url: rawSeries.trailer_url || rawSeries.trailerUrl
            };
            
            const { error: sErr } = await supabase.from('series').upsert(dbSeries);
            if (sErr) {
                console.error('[ADMIN ERROR] Series Upsert Failed:', sErr.message);
                return res.status(400).json({ error: sErr.message });
            }
        }

        if (seriesId && actors !== undefined) {
            await supabase.from('series_actors').delete().eq('series_id', seriesId);
            if (actors.length) await supabase.from('series_actors').insert(actors.map(aid => ({ series_id: seriesId, actor_id: aid })));
        }

        if (seasons !== undefined) {
            const seasonsToUpsert = [];
            const episodesToUpsert = [];
            const episodeServersToDelete = [];
            const episodeServersToInsert = [];

            for (const season of seasons) {
                const { episodes, ...sData } = season;
                if (seriesId || sData.id) {
                    seasonsToUpsert.push({ 
                        id: sData.id,
                        series_id: seriesId || sData.series_id,
                        title: sData.title,
                        number: sData.number,
                        image: sData.image,
                        trailer_url: sData.trailer_url || sData.trailerUrl
                    });
                }

                if (episodes !== undefined) {
                    for (const ep of episodes) {
                        const { watchUrls, number, ...epData } = ep;
                        episodesToUpsert.push({ 
                            id: epData.id,
                            season_id: season.id, 
                            title: epData.title,
                            episode_number: number || 0,
                            image: epData.image,
                            description: epData.description
                        });

                        if (watchUrls !== undefined) {
                            episodeServersToDelete.push(epData.id);
                            if (watchUrls.length) {
                                watchUrls.forEach(srv => {
                                    episodeServersToInsert.push({ episode_id: epData.id, name: srv.name, url: srv.url });
                                });
                            }
                        }
                    }
                }
            }

            // Execute Operations Sequentially to respect Foreign Key constraints
            if (seasonsToUpsert.length) {
                const { error: seaErr } = await supabase.from('seasons').upsert(seasonsToUpsert);
                if (seaErr) {
                    console.error('[BACKEND ERROR] Seasons Upsert Failed:', seaErr.message);
                    throw seaErr;
                }
                console.log(`[BACKEND] Successfully bulk-saved ${seasonsToUpsert.length} seasons`);
            }

            if (episodesToUpsert.length) {
                const { error: epErr } = await supabase.from('episodes').upsert(episodesToUpsert);
                if (epErr) {
                    console.error('[BACKEND ERROR] Episodes Upsert Failed:', epErr.message);
                    throw epErr;
                }
                console.log(`[BACKEND] Successfully bulk-saved ${episodesToUpsert.length} episodes`);
            }

            // Handle Episode Servers (Delete old, insert new)
            if (episodeServersToDelete.length) {
                await supabase.from('episode_servers').delete().in('episode_id', episodeServersToDelete);
                if (episodeServersToInsert.length) {
                    await supabase.from('episode_servers').insert(episodeServersToInsert);
                    console.log(`[BACKEND] Successfully bulk-saved ${episodeServersToInsert.length} episode servers`);
                }
            }
        }
        console.log('[ADMIN SUCCESS] Content Saved Successfully (Sequential)');
        res.json({ message: 'Content saved successfully' });
    } catch (error) { 
        console.error('[ADMIN FATAL] Series Save Error:', error);
        res.status(500).json({ error: error.message }); 
    }
});

app.delete('/api/admin/series/:id', authenticate, auditLog('DELETE_SERIES'), async (req, res) => {
    try {
        const { error } = await supabase.from('series').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ message: 'Series deleted successfully' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

// --- HEALTH CHECK ---
app.get('/', (req, res) => res.send('Rafiq Secure Backend is running 🚀'));

// Export for Vercel
app.use(errorHandler);
module.exports = app;
