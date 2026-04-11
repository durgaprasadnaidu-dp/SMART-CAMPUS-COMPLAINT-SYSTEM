const jwt = require('jsonwebtoken');

module.exports = function (req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ message: 'No token, authorization denied' });
        }

        const token = authHeader.split(' ')[1]; // ✅ extract token

        const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");

        req.user = {
        id: decoded.id || decoded._id
        };

        next();

    } catch (err) {
        console.error("Token error:", err);
        res.status(401).json({ message: 'Invalid token' });
    }
};