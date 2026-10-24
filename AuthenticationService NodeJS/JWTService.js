var jwt = require('jsonwebtoken');

// Pin the algorithm on both sign and verify so a token cannot choose its own (e.g. "none").
const ALGORITHM = 'HS256';

function JWTService(secretKey) {
    if (typeof secretKey !== 'string' || secretKey === '') {
        throw new Error('A non-empty secret key is required.');
    }

    var methods = {};

    function isStringNullOrEmpty(str) {
        return typeof str !== 'string' || str === '';
    }

    /**
     * @param {{ data: object, signOptions?: object }} configurations
     *   data        - claims payload (must be a plain object)
     *   signOptions - extra jsonwebtoken sign options, e.g. { expiresIn: '7d' }
     */
    methods.generateToken = function (configurations) {
        if (configurations === undefined || configurations === null || typeof configurations.data !== 'object' || configurations.data === null) {
            throw new Error('Arguments to create token are not valid.');
        }

        const options = Object.assign({}, configurations.signOptions, { algorithm: ALGORITHM });
        return jwt.sign(configurations.data, secretKey, options);
    }

    methods.isTokenValid = function (token) {
        if (isStringNullOrEmpty(token)) {
            throw new Error('Given token is null or empty.');
        }

        try {
            jwt.verify(token, secretKey, { algorithms: [ALGORITHM] });
            return true;
        } catch (err) {
            return false;
        }
    }

    // Throws (JsonWebTokenError / TokenExpiredError) if the token is invalid.
    methods.getTokenData = function (token) {
        if (isStringNullOrEmpty(token)) {
            throw new Error('Given token is null or empty.');
        }

        return jwt.verify(token, secretKey, { algorithms: [ALGORITHM] });
    }

    return methods;
}

module.exports = {
    JWTService
};
