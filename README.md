# AuthenticationService

The actual articles are written in medium platform, those are just the implementations.

Simple JWT Authentication explanation: https://medium.com/@mmoshikoo/simple-jwt-authentication-explanation-81e930a1a01f

C# Article: https://medium.com/@mmoshikoo/jwt-authentication-using-c-54e0c71f21b0

NodeJS Article: https://medium.com/@mmoshikoo/jwt-authentication-using-nodejs-82a1d8fb8648

Enjoy.

## Configuration (secrets are not stored in the repo)

**C#** - the signing certificate is read from environment variables:

| Variable | Purpose |
| --- | --- |
| `JWT_CERT_PATH` | Full path to the `.pfx` file |
| `JWT_CERT_PASSWORD` | Password of the `.pfx` file |

**NodeJS** - `JWT_SECRET` must be set. Run with `npm install`, `npm start`; tests with `npm test` (Node 18+).
