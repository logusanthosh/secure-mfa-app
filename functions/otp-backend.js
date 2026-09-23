// Backend placeholder: this file is intentionally a secure server-side template.
// It is not a substitute for a production backend, and it must be configured
// with real email and environment variables before use.

const crypto = require('crypto');
const nodemailer = require('nodemailer');

const OTP_TTL_MS = 5 * 60 * 1000;
const OTP_ATTEMPT_LIMIT = 5;
const RESEND_COOLDOWN_MS = 60 * 1000;

function getEmailConfig() {
  const host = String(process.env.EMAIL_HOST || '').trim();
  const port = Number(process.env.EMAIL_PORT || 465);
  const user = String(process.env.EMAIL_USER || '').trim();
  const password = String(process.env.EMAIL_PASSWORD || '').trim();
  const from = String(process.env.EMAIL_FROM || '').trim();

  if (!host || !user || !password || !from) {
    throw new Error('Email backend configuration is missing. Set EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, and EMAIL_FROM.');
  }

  return {
    host,
    port,
    secure: port === 465,
    auth: {
      user,
      pass: password
    },
    from
  };
}

function createConfiguredTransport() {
  const config = getEmailConfig();

  return nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.auth
  });
}

function generateSixDigitOtp() {
  return crypto.randomInt(100000, 999999).toString();
}

function hashOtp(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function createOtpRecord(userId, email, otpValue) {
  const now = Date.now();

  return {
    userId,
    email,
    otpHash: hashOtp(otpValue),
    createdAt: now,
    expiresAt: now + OTP_TTL_MS,
    attemptsUsed: 0,
    maxAttempts: OTP_ATTEMPT_LIMIT,
    used: false,
    invalidated: false,
    lastGeneratedAt: now
  };
}

async function sendOtpEmail(email, otpValue) {
  const config = getEmailConfig();
  const transporter = createConfiguredTransport();

  await transporter.sendMail({
    from: config.from,
    to: email,
    subject: 'Your MFA verification code',
    text: `Your secure verification code is ${otpValue}. This code expires in 5 minutes.`
  });
}

function verifyOtpCandidate(storedOtp, submittedOtp) {
  if (!storedOtp || !submittedOtp) {
    return false;
  }

  const storedHash = String(storedOtp);
  const submittedHash = hashOtp(String(submittedOtp));

  try {
    return crypto.timingSafeEqual(
      Buffer.from(storedHash, 'hex'),
      Buffer.from(submittedHash, 'hex')
    );
  } catch (_error) {
    return false;
  }
}

module.exports = {
  OTP_TTL_MS,
  OTP_ATTEMPT_LIMIT,
  RESEND_COOLDOWN_MS,
  generateSixDigitOtp,
  hashOtp,
  createOtpRecord,
  sendOtpEmail,
  verifyOtpCandidate
};

// Secure backend flow (server-side only):
// 1. Authenticate user with Firebase Auth email/password.
// 2. Generate a secure 6-digit OTP using crypto.randomInt.
// 3. Store only the hash, not the plain OTP value, in the server-side record.
// 4. Send the plain OTP to the user via a trusted email provider.
// 5. Validate expiry, attempts limits, and single-use status on OTP verification.
// 6. Invalidate previous OTP when a new one is generated.
// 7. Only then allow access to the protected dashboard.
