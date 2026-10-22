// middleware/rateLimit.js - V9.0.1 (Fixed: admin detection + auto-clip rate limit)
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { dbGet, dbRun } = require('../database/db');

// ============================================================
// JWT SECRET (ambil dari env atau middleware auth)
// ============================================================
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    try {
        const auth = require('./auth');
        if (auth && auth.JWT_SECRET) JWT_SECRET = auth.JWT_SECRET;
    } catch (e) {
        console.warn('[rateLimit] JWT_SECRET tidak ditemukan di env maupun auth.js');
    }
}

// ============================================================
// GLOBAL LIMITER
// ============================================================
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Terlalu banyak request. Coba lagi nanti.' }
});

// ============================================================
// AUTH LIMITER
// ============================================================
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Terlalu banyak percobaan login. Coba lagi dalam 15 menit.' },
    skipSuccessfulRequests: true
});

// ============================================================
// JOB POLLING LIMITER
// ============================================================
const jobPollingLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false,
    message: { success: false, error: 'Terlalu banyak polling.' }
});

// ============================================================
// PLAN QUOTA
// ============================================================
function getPlanQuota(plan) {
    const quotas = {
        free: parseInt(process.env.FREE_DAILY_QUOTA) || 2,
        pro: parseInt(process.env.PRO_DAILY_QUOTA) || 50,
        business: parseInt(process.env.BUSINESS_DAILY_QUOTA) || 200
    };
    return quotas[plan] || quotas.free;
}

// ============================================================
// QUOTA CACHE (60s TTL)
// ============================================================
const _quotaCache = new Map();
const QUOTA_CACHE_TTL = 60 * 1000;

function _invalidateQuotaCache(userId) {
    if (userId) _quotaCache.delete(userId);
}

function invalidateAllQuotaCache() {
    _quotaCache.clear();
}

// ============================================================
// CEK KUOTA USER (dengan cache)
// ============================================================
async function checkUserQuota(userId) {
    const cached = _quotaCache.get(userId);
    if (cached && (Date.now() - cached.ts) < QUOTA_CACHE_TTL) {
        return cached.data;
    }

    try {
        const user = await dbGet(
            'SELECT plan, daily_quota FROM users WHERE id = ?',
            [userId]
        );

        if (!user) {
            const result = { allowed: false, used: 0, remaining: 0, total: 0, plan: 'free' };
            _quotaCache.set(userId, { data: result, ts: Date.now() });
            return result;
        }

        const plan = user.plan || 'free';
        const totalQuota = user.daily_quota || getPlanQuota(plan);
        const today = new Date().toISOString().slice(0, 10);

        const row = await dbGet(`
            SELECT videos_processed FROM quota_tracking
            WHERE user_id = ? AND date = ?
        `, [userId, today]);

        const used = row ? row.videos_processed : 0;
        const remaining = Math.max(0, totalQuota - used);

        const result = {
            allowed: remaining > 0,
            used,
            remaining,
            total: totalQuota,
            plan
        };

        _quotaCache.set(userId, { data: result, ts: Date.now() });
        return result;
    } catch (e) {
        console.error('checkUserQuota error:', e);
        return { allowed: false, used: 0, remaining: 0, total: 0, plan: 'free' };
    }
}

// ============================================================
// INCREMENT KUOTA
// ============================================================
async function incrementQuota(userId) {
    try {
        const today = new Date().toISOString().slice(0, 10);

        const existing = await dbGet(`
            SELECT id FROM quota_tracking
            WHERE user_id = ? AND date = ?
        `, [userId, today]);

        if (existing) {
            await dbRun(`
                UPDATE quota_tracking
                SET videos_processed = videos_processed + 1
                WHERE user_id = ? AND date = ?
            `, [userId, today]);
        } else {
            await dbRun(`
                INSERT INTO quota_tracking (user_id, date, videos_processed)
                VALUES (?, ?, 1)
            `, [userId, today]);
        }

        await dbRun(`
            UPDATE users SET total_videos = total_videos + 1 WHERE id = ?
        `, [userId]);

        _invalidateQuotaCache(userId);
    } catch (e) {
        console.error('incrementQuota error:', e);
    }
}

// ============================================================
// MIDDLEWARE: REQUIRE QUOTA
// ============================================================
async function requireQuota(req, res, next) {
    if (!req.user) return next();

    const quota = await checkUserQuota(req.user.id);
    if (!quota.allowed) {
        return res.status(429).json({
            success: false,
            error: `Kuota harian habis (${quota.used}/${quota.total}). Coba lagi besok atau upgrade plan.`,
            quota
        });
    }

    req.quota = quota;
    next();
}

// ============================================================
// PREMIUM GATE
// ============================================================
function requirePremium(req, res, next) {
    if (!req.user) {
        return res.status(401).json({ success: false, error: 'Login diperlukan' });
    }

    const plan = (req.user.plan || 'free').toLowerCase();
    const isPremium = ['pro', 'business', 'weekly', 'monthly'].includes(plan);
    const isAdmin = req.user.is_admin === true
                 || req.user.is_admin === 1
                 || req.user.is_admin === 'true';

    if (!isPremium && !isAdmin) {
        console.log(`🔒 [Premium Gate] Blocked user ${req.user.id} (plan: ${plan}) → ${req.originalUrl}`);
        return res.status(403).json({
            success: false,
            error: '🔒 Fitur ini hanya untuk user Pro. Upgrade dulu ya!',
            code: 'PREMIUM_REQUIRED',
            upgrade_url: 'harga.php'
        });
    }

    next();
}

// ============================================================
// V9.186.0: PREMIUM OR TRIAL — Free user dapat 1x percobaan
// ============================================================
function requirePremiumOrTrial(featureName) {
    return async (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ success: false, error: 'Login diperlukan' });
        }

        const plan = (req.user.plan || 'free').toLowerCase();
        const isPremium = ['pro', 'business', 'weekly', 'monthly'].includes(plan);
        const isAdmin = req.user.is_admin === true
                     || req.user.is_admin === 1
                     || req.user.is_admin === 'true';

        if (isPremium || isAdmin) {
            req._trialFeature = null;
            return next();
        }

        try {
            const used = await dbGet(
                "SELECT 1 FROM user_feature_trials WHERE user_id = ? AND feature_name = ?",
                [req.user.id, featureName]
            );

            if (used) {
                console.log(`[Trial Gate] ${featureName} EXHAUSTED user ${req.user.id}`);
                return res.status(403).json({
                    success: false,
                    error: `Percobaan ${featureName} sudah habis. Upgrade ke Pro untuk akses unlimited.`,
                    code: 'TRIAL_EXHAUSTED',
                    feature: featureName,
                    upgrade_url: 'harga.php'
                });
            }

            req._trialFeature = featureName;
            console.log(`[Trial Gate] ${featureName} TRIAL user ${req.user.id}`);
            next();
        } catch (e) {
            console.error('[Trial Gate] Error:', e.message);
            return res.status(500).json({ success: false, error: 'Trial check error' });
        }
    };
}

// ============================================================
// Helper: catat trial setelah request sukses
// ============================================================
async function commitTrial(req) {
    if (!req._trialFeature || !req.user) return;
    try {
        await dbRun(
            "INSERT INTO user_feature_trials (user_id, feature_name) VALUES (?, ?) ON CONFLICT DO NOTHING",
            [req.user.id, req._trialFeature]
        );
        console.log(`[Trial] ${req._trialFeature} recorded for user ${req.user.id}`);
    } catch (e) {
        console.warn("[Trial] commitTrial error:", e.message);
    }
}

// ============================================================
// V9.0.1: HELPER — Get Client IP (aman dari spoofing)
// ============================================================
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        const parts = forwarded.split(',');
        return (parts[0] || '').trim() || 'unknown';
    }
    return req.ip || req.connection?.remoteAddress || 'unknown';
}

// ============================================================
// V9.0.1: DECODE TOKEN (fallback kalau req.user belum ada)
// ============================================================
function decodeTokenFromReq(req) {
    try {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith('Bearer ')) {
            const token = authHeader.substring(7);
            if (JWT_SECRET) {
                return jwt.verify(token, JWT_SECRET);
            }
        }
    } catch (e) {
        // Token invalid, abaikan
    }
    return null;
}

// ============================================================
// V9.0.1: isAdminReq — FIXED (bisa baca token manual)
// ============================================================
function isAdminReq(req) {
    // Cara 1: kalau req.user sudah ada (middleware auth sudah jalan)
    if (req.user) {
        return req.user.is_admin === true
            || req.user.is_admin === 1
            || req.user.is_admin === 'true';
    }
    
    // Cara 2: parse token manual dari header
    const decoded = decodeTokenFromReq(req);
    if (decoded) {
        return decoded.is_admin === true
            || decoded.is_admin === 1
            || decoded.is_admin === 'true';
    }
    
    return false;
}

// ============================================================
// V9.0.1: isPremiumReq — FIXED (bisa baca token manual)
// ============================================================
function isPremiumReq(req) {
    let plan = '';
    
    if (req.user) {
        plan = (req.user.plan || '').toLowerCase();
    } else {
        const decoded = decodeTokenFromReq(req);
        if (decoded && decoded.plan) {
            plan = String(decoded.plan).toLowerCase();
        }
    }
    
    return ['pro', 'business', 'weekly', 'monthly'].includes(plan);
}

// ============================================================
// V9.0.0: ABUSE DETECTION STORE
// ============================================================
const ABUSE_WINDOW_MS = 15 * 60 * 1000;
const ABUSE_FAIL_THRESHOLD = 15;
const ABUSE_BLOCK_MS = 60 * 60 * 1000;
const ABUSE_CLEANUP_INTERVAL = 5 * 60 * 1000;

const abuseStore = new Map();

function isIpBlocked(ip) {
    const entry = abuseStore.get(ip);
    if (!entry) return false;
    if (entry.blockedUntil && entry.blockedUntil > Date.now()) return true;
    if (entry.blockedUntil && entry.blockedUntil <= Date.now()) {
        abuseStore.delete(ip);
    }
    return false;
}

function recordAbuse(ip, reason) {
    const now = Date.now();
    let entry = abuseStore.get(ip);
    if (!entry) {
        entry = { fails: [], blockedUntil: 0, reason: '' };
        abuseStore.set(ip, entry);
    }

    entry.fails = entry.fails.filter(t => now - t < ABUSE_WINDOW_MS);
    entry.fails.push(now);
    entry.reason = reason;

    if (entry.fails.length >= ABUSE_FAIL_THRESHOLD) {
        if (!entry.blockedUntil || entry.blockedUntil <= now) {
            entry.blockedUntil = now + ABUSE_BLOCK_MS;
            console.warn(`🚫 [AbuseGuard] IP ${ip} BLOCKED 1 jam — ${entry.fails.length} fails (${reason})`);
        }
    }
}

function unblockIp(ip) {
    abuseStore.delete(ip);
}

function getAbuseStats() {
    const stats = [];
    const now = Date.now();
    for (const [ip, entry] of abuseStore.entries()) {
        stats.push({
            ip,
            fails: entry.fails.filter(t => now - t < ABUSE_WINDOW_MS).length,
            blocked: entry.blockedUntil > now,
            blockedUntil: entry.blockedUntil ? new Date(entry.blockedUntil).toISOString() : null,
            reason: entry.reason,
        });
    }
    return stats;
}

setInterval(() => {
    const now = Date.now();
    let removed = 0;
    for (const [ip, entry] of abuseStore.entries()) {
        const allExpired = entry.fails.every(t => now - t >= ABUSE_WINDOW_MS);
        const blockExpired = !entry.blockedUntil || entry.blockedUntil <= now;
        if (allExpired && blockExpired) {
            abuseStore.delete(ip);
            removed++;
        }
    }
    if (removed > 0) {
        console.log(`🧹 [AbuseGuard] Cleanup: ${removed} IP entries removed`);
    }
}, ABUSE_CLEANUP_INTERVAL);

// ============================================================
// V9.0.0: ABUSE GUARD MIDDLEWARE
// ============================================================
function abuseGuard(req, res, next) {
    if (isAdminReq(req)) return next();

    const ip = getClientIp(req);
    if (isIpBlocked(ip)) {
        const entry = abuseStore.get(ip);
        const remaining = Math.ceil((entry.blockedUntil - Date.now()) / 1000 / 60);
        console.warn(`🚫 [AbuseGuard] Blocked ${ip} (${remaining} min left, reason: ${entry.reason})`);
        return res.status(403).json({
            success: false,
            code: 'IP_BLOCKED',
            error: `Akses diblokir sementara. Coba lagi dalam ${remaining} menit.`,
            retry_after_sec: Math.ceil((entry.blockedUntil - Date.now()) / 1000),
        });
    }
    next();
}

// ============================================================
// V9.0.0: RATE KEY GENERATOR
// ============================================================
const analyzeKeyGenerator = (req) => {
    if (req.user && req.user.id) return `user_${req.user.id}`;
    // Fallback: decode token untuk dapat userId
    const decoded = decodeTokenFromReq(req);
    if (decoded && decoded.userId) return `user_${decoded.userId}`;
    return `ip_${getClientIp(req)}`;
};

// ============================================================
// V9.0.0: ANALYZE — BURST LIMITER (30 detik)
// ============================================================
const analyzeBurstLimiter = rateLimit({
    windowMs: 30 * 1000,
    max: (req) => {
        if (isAdminReq(req)) return 9999;
        if (isPremiumReq(req)) return 5;
        return 2;
    },
    keyGenerator: analyzeKeyGenerator,
    standardHeaders: false,
    legacyHeaders: false,
    handler: (req, res) => {
        const ip = getClientIp(req);
        recordAbuse(ip, 'burst_limit');
        console.warn(`🚫 [RateLimit] Analyze burst limit — ${isAdminReq(req) ? 'admin' : req.user ? 'user ' + req.user.id : 'guest ' + ip}`);
        res.status(429).json({
            success: false,
            code: 'BURST_LIMITED',
            error: 'Terlalu cepat! Tunggu beberapa detik sebelum upload lagi.',
            retry_after_sec: 30,
        });
    },
    skip: (req) => isAdminReq(req)
});

// ============================================================
// V9.0.0: ANALYZE — ROLLING LIMITER (15 menit)
// ============================================================
const analyzeRollingLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: (req) => {
        if (isAdminReq(req)) return 9999;
        if (isPremiumReq(req)) return 30;
        if (req.user) return 5;
        return 5;
    },
    keyGenerator: analyzeKeyGenerator,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const ip = getClientIp(req);
        recordAbuse(ip, 'rolling_limit');
        const isGuest = !req.user;
        const isPremium = isPremiumReq(req);
        console.warn(`🚫 [RateLimit] Analyze rolling blocked — ${isGuest ? 'guest ' + ip : 'user ' + req.user.id}`);
        res.status(429).json({
            success: false,
            code: 'RATE_LIMITED',
            error: isGuest
                ? 'Terlalu banyak request. Daftar untuk kuota lebih besar.'
                : isPremium
                    ? 'Slow down! Tunggu 15 menit lagi.'
                    : 'Terlalu banyak request. Upgrade ke Premium untuk limit lebih tinggi.',
            cta: isGuest ? 'register' : (!isPremium ? 'upgrade' : null),
            cta_url: isGuest ? '/register.php' : (!isPremium ? '/harga.php' : null),
            retry_after_sec: 900
        });
    },
    skip: (req) => isAdminReq(req)
});

// ============================================================
// V9.0.0: ANALYZE — HOURLY LIMITER (1 jam)
// ============================================================
const analyzeHourlyLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: (req) => {
        if (isAdminReq(req)) return 9999;
        if (isPremiumReq(req)) return 60;
        if (req.user) return 20;
        return 10;
    },
    keyGenerator: analyzeKeyGenerator,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        const ip = getClientIp(req);
        recordAbuse(ip, 'hourly_limit');
        const isGuest = !req.user;
        const isPremium = isPremiumReq(req);
        console.warn(`🚫 [RateLimit] Analyze hourly blocked — ${isGuest ? 'guest ' + ip : 'user ' + req.user.id}`);
        res.status(429).json({
            success: false,
            code: 'RATE_LIMITED',
            error: isGuest
                ? 'Limit per jam tercapai. Daftar untuk limit lebih tinggi.'
                : isPremium
                    ? 'Limit per jam tercapai. Tunggu 1 jam lagi.'
                    : 'Limit per jam tercapai. Upgrade untuk limit lebih tinggi.',
            cta: isGuest ? 'register' : (!isPremium ? 'upgrade' : null),
            cta_url: isGuest ? '/register.php' : (!isPremium ? '/harga.php' : null),
            retry_after_sec: 3600
        });
    },
    skip: (req) => isAdminReq(req)
});

// ============================================================
// V9.0.0: ANALYZE LIMITER (COMBINATION)
// ============================================================
const analyzeLimiter = [
    abuseGuard,
    analyzeBurstLimiter,
    analyzeRollingLimiter,
    analyzeHourlyLimiter,
];

// ============================================================
// V9.0.1: AUTO-CLIP LIMITER (FIXED)
// ============================================================
const autoClipLimiter = [
    abuseGuard,
    rateLimit({
        windowMs: 30 * 60 * 1000,
        max: (req) => {
            if (isAdminReq(req)) return 9999;
            if (isPremiumReq(req)) return 10;
            // Non-premium: 5 request per 30 menit (bukan 0!)
            // Kalau mau blokir total, tangani di route handler dengan pesan "Upgrade"
            return 5;
        },
        keyGenerator: analyzeKeyGenerator,
        standardHeaders: true,
        legacyHeaders: false,
        handler: (req, res) => {
            const ip = getClientIp(req);
            recordAbuse(ip, 'autoclip_limit');
            const isAdmin = isAdminReq(req);
            const isPremium = isPremiumReq(req);
            console.warn(`🚫 [RateLimit] AutoClip blocked — ${isAdmin ? 'admin' : req.user ? 'user ' + req.user.id : 'guest ' + ip}`);
            res.status(429).json({
                success: false,
                code: 'RATE_LIMITED',
                error: isPremium
                    ? 'Terlalu banyak Auto-Clip. Tunggu 30 menit lagi.'
                    : 'Limit Auto-Clip tercapai. Upgrade ke Premium untuk limit lebih tinggi.',
                cta: isPremium ? null : 'upgrade',
                cta_url: isPremium ? null : '/harga.php',
                retry_after_sec: 1800
            });
        },
        skip: (req) => isAdminReq(req)
    })
];

// ============================================================
// EXPORTS
// ============================================================
module.exports = {
    globalLimiter,
    authLimiter,
    requireQuota,
    incrementQuota,
    checkUserQuota,
    jobPollingLimiter,
    requirePremium,
    requirePremiumOrTrial,
    commitTrial,
    analyzeLimiter,
    autoClipLimiter,
    _invalidateQuotaCache,
    invalidateAllQuotaCache,
    abuseGuard,
    getAbuseStats,
    unblockIp,
    getClientIp,
    recordAbuse,
};