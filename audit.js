const auditLog = (action) => (req, res, next) => {
    const originalJson = res.json;
    res.json = function(data) {
        console.log('[AUDIT]', {
            timestamp: new Date().toISOString(),
            action,
            adminId: req.admin?.id,
            adminUser: req.admin?.username,
            ip: req.ip,
            endpoint: req.originalUrl,
            status: res.statusCode
        });
        return originalJson.call(this, data);
    };
    next();
};

module.exports = auditLog;
