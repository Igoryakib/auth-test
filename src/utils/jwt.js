const jwt = require('jsonwebtoken');

const options = {
    expiresIn: '7d',
};

exports.generate = (payload) => jwt.sign(payload, process.env.JWT_SECRET, options);

exports.verify = (token) => jwt.verify(token, process.env.JWT_SECRET);