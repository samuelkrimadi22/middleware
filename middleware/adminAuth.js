// middleware/adminAuth.js - Admin Authorization Middleware
const { requireAuth } = require('./auth');
const { dbGet } = require('../database/db');

/**
 * Middleware: requireAuth + require admin role
 */
async function requireAdmin(req, res, next) {
    // Jalankan requireAuth dulu
    requireAuth(req, res, async () => {
        try {
            const user = await dbGet('SELECT is_admin FROM users WHERE id = ?', [req.user.id]);
            if (!user || !user.is_admin) {
                return res.status(403).json({
                    success: false,
                    error: 'Akses ditolak. Hanya admin yang bisa mengakses.'
                });
            }
            req.user.is_admin = true;
            next();
        } catch (error) {
            return res.status(500).json({ success: false, error: error.message });
        }
    });
}

module.exports = { requireAdmin };