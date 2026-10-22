// middleware/auditMiddleware.js
// V9.8.0: Auto-log semua write action admin (POST/PUT/PATCH/DELETE)
const { logAdminAction } = require("../services/auditLog");

function auditAdminActions(req, res, next) {
    // Skip GET requests (read-only, tidak perlu log)
    if (req.method === "GET") return next();
    
    // Capture original res.json
    const originalJson = res.json.bind(res);
    
    res.json = function(data) {
        // Log HANYA kalau:
        // - Status 2xx (sukses)
        // - Ada req.user (admin yang login)
        // - Data response tidak menunjukkan error (success !== false)
        try {
            if (
                res.statusCode >= 200 && 
                res.statusCode < 300 && 
                req.user && 
                data?.success !== false
            ) {
                const method = req.method;
                const path = req.originalUrl || req.path;
                const username = req.user.username || `id:${req.user.id}`;
                
                // Clean path: buang query string
                const cleanPath = path.split("?")[0];
                
                const details = `Admin "${username}" → ${method} ${cleanPath}`;
                const action = `${method}_${cleanPath.replace(/\/\d+/g, "/:id")}`;
                
                // Non-blocking: jangan delay response
                logAdminAction(
                    req.user.id,
                    action,
                    details,
                    req
                ).catch(e => console.error("⚠️  Audit middleware error:", e.message));
            }
        } catch (e) {
            console.error("⚠️  Audit middleware exception:", e.message);
        }
        
        return originalJson(data);
    };
    
    next();
}

module.exports = auditAdminActions;
