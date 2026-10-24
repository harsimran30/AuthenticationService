var { JWTService } = require('./JWTService');

// The signing secret must come from the environment, never from source control.
// e.g. (PowerShell)  $env:JWT_SECRET = "<long random value>"
function getConfigurations(dataModel) {
    const secretKey = process.env.JWT_SECRET;
    if (!secretKey) {
        throw new Error('Environment variable JWT_SECRET is not set.');
    }

    return {
        data: dataModel,
        secretKey: secretKey,
        signOptions: {
            expiresIn: '7d'
        }
    };
}

(function main() {
    try {
        const model = {
            name: 'Moshe Binieli',
            email: 'mmoshikoo@gmail.com'
        };

        const configurations = getConfigurations(model);
        const jwtService = JWTService(configurations.secretKey);

        const token = jwtService.generateToken(configurations);

        if (!jwtService.isTokenValid(token)) {
            throw new Error('Given token is not valid.');
        }

        console.log(jwtService.getTokenData(token));
    } catch (ex) {
        console.error(ex);
        process.exitCode = 1;
    }
})();
