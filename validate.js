const { body, validationResult } = require('express-validator');

const validateMovie = [
    body('id').optional().isString().trim().escape(),
    body('title').trim().isLength({ min: 1, max: 255 }).withMessage('Title is required').escape(),
    body('description').optional().trim().isLength({ max: 5000 }).escape(),
    body('rating').optional().isFloat({ min: 0, max: 10 }).toFloat(),
    body('releaseDate').optional().trim().isLength({ max: 50 }).escape(),
    body('image').optional().isURL().withMessage('Invalid image URL'),
    body('background').optional().isURL().withMessage('Invalid background URL'),
    body('trailerUrl').optional().isURL().withMessage('Invalid trailer URL'),
    body('actors').optional().isArray(),
    body('watchUrls').optional().isArray(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ error: 'Invalid input', details: errors.array() });
        }
        next();
    }
];

const validateActor = [
    body('id').trim().isLength({ min: 1, max: 50 }).escape(),
    body('name').trim().isLength({ min: 1, max: 255 }).escape(),
    body('image').optional().isURL(),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) return res.status(400).json({ error: 'Invalid input', details: errors.array() });
        next();
    }
];

module.exports = { validateMovie, validateActor };
