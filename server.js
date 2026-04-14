const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
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
    : ['https://rafiq-backend1.vercel.app', 'electron://rafiq', 'http://localhost:5173', 'https://رفيق.vip', 'https://www.رفيق.vip'];

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            imgSrc: ["'self'", "https:", "data:", "blob:"],
            connectSrc: ["'self'", "https://*.supabase.co", "https://*.googlesyndication.com"],
            frameSrc: ["'self'", "*"], // Required for video iframes
            objectSrc: ["'none'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"]
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

const DOOD_API_KEY = '562660bwqmd4fjnts767rz';
const DOOD_BASE_URL = 'https://doodapi.co/api';

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

const mapMessage = (m) => ({
    id: m.id,
    title: m.title,
    content: m.content,
    backgroundUrl: m.background_url || m.backgroundUrl || '',
    ctaText: m.cta_text || m.ctaText || '',
    ctaUrl: m.cta_url || m.ctaUrl || '',
    durationSeconds: m.duration_seconds || m.durationSeconds || 0,
    triggerDelaySeconds: m.trigger_delay_seconds || m.triggerDelaySeconds || 0,
    isActive: m.is_active !== undefined ? m.is_active : (m.isActive !== undefined ? m.isActive : true),
    createdAt: m.created_at || m.createdAt
});

const toDBMessage = (m) => ({
    id: m.id,
    title: m.title,
    content: m.content,
    background_url: m.backgroundUrl,
    cta_text: m.ctaText,
    cta_url: m.ctaUrl,
    duration_seconds: m.durationSeconds,
    trigger_delay_seconds: m.triggerDelaySeconds,
    is_active: m.isActive
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

app.get('/api/public/messages', async (req, res) => {
    try {
        const { data, error } = await supabase.from('messages').select('*').eq('is_active', true).order('created_at', { ascending: false });
        if (error) throw error;
        res.json(data ? data.map(mapMessage) : []);
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
                    const seasonObj = { id: sData.id };
                    if (sData.title !== undefined) seasonObj.title = sData.title;
                    if (sData.number !== undefined) seasonObj.number = sData.number;
                    if (sData.image !== undefined) seasonObj.image = sData.image;
                    const trailer = sData.trailer_url || sData.trailerUrl;
                    if (trailer !== undefined) seasonObj.trailer_url = trailer;
                    
                    // Only include series_id if we have it, to avoid nullifying existing links
                    const finalSeriesId = seriesId || sData.series_id;
                    if (finalSeriesId) seasonObj.series_id = finalSeriesId;

                    seasonsToUpsert.push(seasonObj);
                }

                if (episodes !== undefined) {
                    for (const ep of episodes) {
                        const { watchUrls, number, ...epData } = ep;
                        const epObj = { id: epData.id };
                        if (epData.title !== undefined) epObj.title = epData.title;
                        if (number !== undefined) epObj.episode_number = number || 0;
                        if (epData.image !== undefined) epObj.image = epData.image;
                        if (epData.description !== undefined) epObj.description = epData.description;
                        
                        // Relationship guard
                        const finalSeasonId = season.id || epData.season_id;
                        if (finalSeasonId) epObj.season_id = finalSeasonId;

                        episodesToUpsert.push(epObj);

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

app.post('/api/admin/messages', authenticate, auditLog('SAVE_MESSAGE'), async (req, res) => {
    try {
        const dbMsg = toDBMessage(req.body);
        const { error } = await supabase.from('messages').upsert(dbMsg);
        if (error) throw error;
        res.json({ message: 'Message saved successfully' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

app.delete('/api/admin/messages/:id', authenticate, auditLog('DELETE_MESSAGE'), async (req, res) => {
    try {
        const { error } = await supabase.from('messages').delete().eq('id', req.params.id);
        if (error) throw error;
        res.json({ message: 'Message deleted successfully' });
    } catch (error) { res.status(400).json({ error: error.message }); }
});

// --- DOODSTREAM PROXY ---
app.get('/api/admin/doodstream/account', authenticate, async (req, res) => {
    try {
        const response = await fetch(`${DOOD_BASE_URL}/account/info?key=${DOOD_API_KEY}`);
        const data = await response.json();
        res.json(data);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/doodstream/files', authenticate, async (req, res) => {
    try {
        const { fld_id = 0 } = req.query;
        const response = await fetch(`${DOOD_BASE_URL}/folder/list?key=${DOOD_API_KEY}&fld_id=${fld_id}`);
        const data = await response.json();
        res.json(data);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/admin/doodstream/remote-upload', authenticate, async (req, res) => {
    try {
        const { url, title } = req.body;
        const apiUrl = `${DOOD_BASE_URL}/upload/url?key=${DOOD_API_KEY}&url=${encodeURIComponent(url)}${title ? `&new_title=${encodeURIComponent(title)}` : ''}`;
        const response = await fetch(apiUrl);
        const data = await response.json();
        res.json(data);
    } catch (error) { res.status(500).json({ error: error.message }); }
});



// --- HEALTH CHECK ---
app.get('/', (req, res) => res.send('Rafiq Secure Backend is running 🚀'));

// Serve Static Files from Website build
const websiteDistPath = path.join(__dirname, '../website/dist');
if (fs.existsSync(websiteDistPath)) {
    app.use(express.static(websiteDistPath));
    console.log('[BACKEND] Serving website from:', websiteDistPath);
    
    // Catch-all for React Router
    app.get('*', (req, res) => {
        if (!req.path.startsWith('/api')) {
            res.sendFile(path.join(websiteDistPath, 'index.html'));
        } else {
            res.status(404).json({ error: 'API route not found' });
        }
    });
}

// Export for Vercel
app.use(errorHandler);

// Listen Locally if not in Vercel/Serverless environment
if (require.main === module) {
    app.listen(PORT, '0.0.0.0', () => {
        console.log(`
        🚀 Rafiq Backend is ready!
        🌍 Access locally: http://localhost:${PORT}
        🌐 Website: https://رفيق.vip
        `);
    });
}

module.exports = app;
