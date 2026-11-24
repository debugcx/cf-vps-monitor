import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptTotpSecret,
  encryptTotpSecret,
  generateRecoveryCodes,
  hashRecoveryCode,
  normalizeRecoveryCode,
} from './mfa.ts';

const env = { JWT_SECRET: '0123456789abcdef0123456789abcdef' };

test('encrypts TOTP secrets with random IV and user-bound authentication', async () => {
  const first = await encryptTotpSecret('JBSWY3DPEHPK3PXP', 'user-a', env);
  const second = await encryptTotpSecret('JBSWY3DPEHPK3PXP', 'user-a', env);

  assert.notEqual(first, second);
  assert.equal(await decryptTotpSecret(first, 'user-a', env), 'JBSWY3DPEHPK3PXP');
  await assert.rejects(() => decryptTotpSecret(first, 'user-b', env));
  const [version, iv, data] = first.split('.');
  const tamperedData = `${data.startsWith('A') ? 'B' : 'A'}${data.slice(1)}`;
  await assert.rejects(() => decryptTotpSecret(`${version}.${iv}.${tamperedData}`, 'user-a', env));
  await assert.rejects(() => decryptTotpSecret(first, 'user-a', { JWT_SECRET: 'abcdef0123456789abcdef0123456789' }));
});

test('generates eight unique 120-bit recovery codes and stable hashes', async () => {
  const result = await generateRecoveryCodes(env);
  assert.equal(result.codes.length, 8);
  assert.equal(result.hashes.length, 8);
  assert.equal(new Set(result.codes).size, 8);
  assert.equal(new Set(result.hashes).size, 8);
  for (const code of result.codes) {
    assert.match(code, /^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){5}$/);
  }

  const normalized = normalizeRecoveryCode(` ${result.codes[0].toLowerCase()} `);
  assert.equal(normalized, result.codes[0].replaceAll('-', ''));
  assert.equal(await hashRecoveryCode(result.codes[0], env), result.hashes[0]);
  assert.equal(await hashRecoveryCode(normalized, env), result.hashes[0]);
});

test('rejects malformed recovery codes', () => {
  assert.throws(() => normalizeRecoveryCode('short'), /恢复码/);
  assert.throws(() => normalizeRecoveryCode('ABCD-EFGH-IJKL-MNOP-QRST-UVWX!'), /恢复码/);
});

test('keeps MFA material stable across JWT_SECRET rotation when MFA_SECRET is configured', async () => {
  const withMfaSecret = {
    JWT_SECRET: '0123456789abcdef0123456789abcdef',
    MFA_SECRET: 'fedcba9876543210fedcba9876543210',
  };
  const afterJwtRotation = {
    JWT_SECRET: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    MFA_SECRET: 'fedcba9876543210fedcba9876543210',
  };

  // 轮换会话签名密钥不能废掉已绑定的验证器。
  const encrypted = await encryptTotpSecret('JBSWY3DPEHPK3PXP', 'user-a', withMfaSecret);
  assert.equal(await decryptTotpSecret(encrypted, 'user-a', afterJwtRotation), 'JBSWY3DPEHPK3PXP');

  // 恢复码的 HMAC 同样要保持稳定。
  const codes = await generateRecoveryCodes(withMfaSecret);
  assert.equal(await hashRecoveryCode(codes.codes[0], afterJwtRotation), codes.hashes[0]);

  // 但换掉 MFA_SECRET 本身仍然必须解不开 —— 说明它确实在起作用。
  await assert.rejects(() => decryptTotpSecret(encrypted, 'user-a', {
    ...afterJwtRotation,
    MFA_SECRET: '11111111111111111111111111111111',
  }));
});

test('falls back to JWT_SECRET when MFA_SECRET is absent or too short', async () => {
  const base = { JWT_SECRET: '0123456789abcdef0123456789abcdef' };
  const encrypted = await encryptTotpSecret('JBSWY3DPEHPK3PXP', 'user-a', base);

  // 短于 32 字节的 MFA_SECRET 视为未配置，仍然回退到 JWT_SECRET。
  const shortSecret = { ...base, MFA_SECRET: 'too-short' };
  assert.equal(await decryptTotpSecret(encrypted, 'user-a', shortSecret), 'JBSWY3DPEHPK3PXP');

  // 回退状态下，轮换 JWT_SECRET 依然会废掉密文 —— 这正是要靠 MFA_SECRET 规避的坑。
  await assert.rejects(() => decryptTotpSecret(encrypted, 'user-a', {
    JWT_SECRET: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  }));
});
