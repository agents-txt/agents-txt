import { describe, it, expect } from 'vitest';
import { parseJwt, verifyEd25519, jwkThumbprint, assertClaims } from '../jwt.js';
import { generateKeypair, signJwt, thumbprint } from './helpers.js';

describe('parseJwt', () => {
  it('parses a valid JWT into header, payload, signedData, signature', async () => {
    const { publicJwk, privateKey } = await generateKeypair();
    const token = await signJwt({ typ: 'host+jwt', sub: 'test' }, {}, privateKey);
    const parsed = parseJwt(token);
    expect(parsed).not.toBeNull();
    expect(parsed!.header).toHaveProperty('alg', 'EdDSA');
    expect(parsed!.payload).toHaveProperty('typ', 'host+jwt');
    expect(parsed!.payload).toHaveProperty('sub', 'test');
    expect(typeof parsed!.signedData).toBe('string');
    expect(parsed!.signature).toBeInstanceOf(Uint8Array);
    // publicJwk referenced to avoid unused var lint warning
    void publicJwk;
  });

  it('returns null for malformed token (wrong number of parts)', () => {
    expect(parseJwt('not.a.valid.jwt.here')).toBeNull();
    expect(parseJwt('onlyone')).toBeNull();
    expect(parseJwt('two.parts')).toBeNull();
  });

  it('returns null when header is not valid base64url JSON', () => {
    expect(parseJwt('!!!.payload.sig')).toBeNull();
  });
});

describe('verifyEd25519', () => {
  it('returns true for a valid signature', async () => {
    const { publicJwk, privateKey } = await generateKeypair();
    const token = await signJwt({ sub: 'ok' }, {}, privateKey);
    const parsed = parseJwt(token)!;
    const ok = await verifyEd25519(parsed.signedData, parsed.signature, publicJwk);
    expect(ok).toBe(true);
  });

  it('returns false when the payload is tampered with different valid JSON', async () => {
    const { publicJwk, privateKey } = await generateKeypair();
    const token = await signJwt({ sub: 'ok' }, {}, privateKey);
    const parts = token.split('.');
    // Replace payload with a different valid base64url-encoded JSON so parseJwt succeeds
    const differentPayload = btoa(JSON.stringify({ sub: 'tampered', iat: 0, exp: 9999999999 }))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const tampered = `${parts[0]}.${differentPayload}.${parts[2]}`;
    const parsed = parseJwt(tampered)!;
    expect(parsed).not.toBeNull();
    const ok = await verifyEd25519(parsed.signedData, parsed.signature, publicJwk);
    expect(ok).toBe(false);
  });

  it('returns false when verified against the wrong public key', async () => {
    const { privateKey } = await generateKeypair();
    const { publicJwk: wrongPublicJwk } = await generateKeypair();
    const token = await signJwt({ sub: 'ok' }, {}, privateKey);
    const parsed = parseJwt(token)!;
    const ok = await verifyEd25519(parsed.signedData, parsed.signature, wrongPublicJwk);
    expect(ok).toBe(false);
  });

  it('returns false for a truncated signature', async () => {
    const { publicJwk, privateKey } = await generateKeypair();
    const token = await signJwt({ sub: 'ok' }, {}, privateKey);
    const parsed = parseJwt(token)!;
    const ok = await verifyEd25519(parsed.signedData, parsed.signature.slice(0, 16), publicJwk);
    expect(ok).toBe(false);
  });
});

describe('jwkThumbprint', () => {
  it('returns a non-empty base64url string', async () => {
    const { publicJwk } = await generateKeypair();
    const t = await jwkThumbprint(publicJwk);
    expect(typeof t).toBe('string');
    expect(t.length).toBeGreaterThan(0);
    expect(t).not.toMatch(/[+/=]/);
  });

  it('is deterministic — same key always produces the same thumbprint', async () => {
    const { publicJwk } = await generateKeypair();
    const t1 = await jwkThumbprint(publicJwk);
    const t2 = await jwkThumbprint(publicJwk);
    expect(t1).toBe(t2);
  });

  it('produces different thumbprints for different keys', async () => {
    const { publicJwk: a } = await generateKeypair();
    const { publicJwk: b } = await generateKeypair();
    expect(await jwkThumbprint(a)).not.toBe(await jwkThumbprint(b));
  });

  it('matches the helper thumbprint function', async () => {
    const { publicJwk } = await generateKeypair();
    expect(await jwkThumbprint(publicJwk)).toBe(await thumbprint(publicJwk));
  });
});

describe('assertClaims', () => {
  it('returns null for a valid token', () => {
    const now = Math.floor(Date.now() / 1000);
    expect(assertClaims({ iat: now - 5, exp: now + 55 })).toBeNull();
  });

  it('returns an error string for an expired token', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = assertClaims({ exp: now - 1 });
    expect(result).toBe('token expired');
  });

  it('returns an error string when iat is in the future beyond clock skew', () => {
    const now = Math.floor(Date.now() / 1000);
    const result = assertClaims({ iat: now + 60 });
    expect(result).toBe('token not yet valid');
  });

  it('allows a small iat clock skew (within 30s)', () => {
    const now = Math.floor(Date.now() / 1000);
    expect(assertClaims({ iat: now + 29 })).toBeNull();
  });

  it('returns null when exp and iat are absent', () => {
    expect(assertClaims({})).toBeNull();
  });
});
