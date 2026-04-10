const errorHandler = (err, req, res, next) => {
    console.error('[SERVER ERROR]', {
        message: err.message,
        stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
        path: req.path,
        method: req.method,
        ip: req.ip
    });

    const isDev = process.env.NODE_ENV === 'development';
    
    res.status(err.status || 500).json({
        error: isDev ? err.message : 'An internal server error occurred',
        ...(isDev && { stack: err.stack })
    });
};

module.exports = errorHandler;
