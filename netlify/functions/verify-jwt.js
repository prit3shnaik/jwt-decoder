const crypto = require('crypto');

/* Decode Base64URL to string */
function base64urlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString('utf-8');
}

exports.handler = async (event) => {
  /* Only accept POST requests */
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ valid: false, error: 'Method not allowed' })
    };
  }

  try {
    const body = JSON.parse(event.body);
    const token = (body.token || '').trim();
    const secret = body.secret || '';

    /* Validate inputs */
    if (!token || !secret) {
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ valid: false, error: 'Both token and secret are required' })
      };
    }

    /* Split token into 3 parts */
    const parts = token.split('.');
    if (parts.length !== 3) {
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ valid: false, error: 'Invalid JWT structure — must have 3 parts separated by dots' })
      };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    /* Decode header and check algorithm */
    let header;
    try {
      const headerJson = base64urlDecode(headerB64);
      header = JSON.parse(headerJson);
    } catch (e) {
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ valid: false, error: 'Cannot decode JWT header' })
      };
    }

    if (header.alg !== 'HS256') {
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ valid: false, error: 'Unsupported algorithm: ' + (header.alg || 'none') + '. Only HS256 is supported.' })
      };
    }

    /* Compute HMAC-SHA256 of header.payload using the secret */
    const signingInput = headerB64 + '.' + payloadB64;
    const computedSig = crypto
      .createHmac('sha256', secret)
      .update(signingInput)
      .digest('base64')
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

        /* Compare computed signature with the one in the token */
    let isValid = false;
    try {
      const sigBuf = Buffer.from(signatureB64);
      const computedBuf = Buffer.from(computedSig);

      // timingSafeEqual requires buffers of the exact same length
      if (sigBuf.length === computedBuf.length) {
        isValid = crypto.timingSafeEqual(sigBuf, computedBuf);
      }
    } catch (e) {
      isValid = false;
    }

    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        valid: isValid,
        algorithm: 'HS256',
        error: isValid ? null : 'Signature does not match the provided secret'
      })
    };
