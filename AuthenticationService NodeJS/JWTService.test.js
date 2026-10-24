const test = require('node:test');
const assert = require('node:assert');
const jwt = require('jsonwebtoken');
const { JWTService } = require('./JWTService');

const SECRET = 'unit-test-secret';
const config = { data: { name: 'A', email: 'a@example.com' }, signOptions: { expiresIn: '1h' } };

test('requires a non-empty secret', () => {
    assert.throws(() => JWTService(''), /secret key/);
    assert.throws(() => JWTService(undefined), /secret key/);
});

test('generates a token that validates and round-trips its data', () => {
    const svc = JWTService(SECRET);
    const token = svc.generateToken(config);
    assert.strictEqual(svc.isTokenValid(token), true);
    const data = svc.getTokenData(token);
    assert.strictEqual(data.name, 'A');
    assert.strictEqual(data.email, 'a@example.com');
});

test('rejects invalid configurations', () => {
    const svc = JWTService(SECRET);
    assert.throws(() => svc.generateToken(null), /not valid/);
    assert.throws(() => svc.generateToken({}), /not valid/);
});

test('rejects a token signed with a different secret', () => {
    const token = JWTService('other-secret').generateToken(config);
    assert.strictEqual(JWTService(SECRET).isTokenValid(token), false);
});

test('rejects an unsigned (alg=none) token', () => {
    const token = jwt.sign(config.data, '', { algorithm: 'none' });
    assert.strictEqual(JWTService(SECRET).isTokenValid(token), false);
});

test('rejects an expired token', () => {
    const svc = JWTService(SECRET);
    const token = svc.generateToken({ data: config.data, signOptions: { expiresIn: -10 } });
    assert.strictEqual(svc.isTokenValid(token), false);
    assert.throws(() => svc.getTokenData(token), /expired/);
});

test('null or empty token throws', () => {
    assert.throws(() => JWTService(SECRET).isTokenValid(''), /null or empty/);
    assert.throws(() => JWTService(SECRET).getTokenData(undefined), /null or empty/);
});
