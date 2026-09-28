require('dotenv').config();

const path = require('path');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const {
  generateSixDigitOtp,
  hashOtp,
  OTP_TTL_MS,
  OTP_ATTEMPT_LIMIT,
  RESEND_COOLDOWN_MS
} = require('./functions/otp-backend');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const APP_NAME = 'Secure MFA App';
const activeChallenges = new Map();
const emailChallengeMap = new Map();
const requestCooldowns = new Map();

const allowedOrigins = new Set([
  'http://localhost:5500',
  'http://127.0.0.1:5500',
  'http://localhost:8080',
  'http://localhost:3000',
  'https://secure-mfa-app.onrender.com',
  'https://mfa-user.web.app',
  'https://mfa-user.firebaseapp.com'
]);

function getSmtpConfig() {
  const host = String(process.env.EMAIL_HOST || '').trim();
  const port = Number(process.env.EMAIL_PORT || 465);
  const user = String(process.env.EMAIL_USER || '').trim();
  const password = String(process.env.EMAIL_PASSWORD || '').trim();
  const from = String(process.env.EMAIL_FROM || '').trim();

  if (!host || !user || !password || !from) {
    throw new Error('SMTP configuration is incomplete. Set EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, and EMAIL_FROM in the environment.');
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

function getSmtpDiagnostics() {
  return {
    hostConfigured: Boolean(String(process.env.EMAIL_HOST || '').trim()),
    portConfigured: Boolean(String(process.env.EMAIL_PORT || '').trim()),
    usernameConfigured: Boolean(String(process.env.EMAIL_USER || '').trim()),
    passwordConfigured: Boolean(String(process.env.EMAIL_PASSWORD || '').trim()),
    fromConfigured: Boolean(String(process.env.EMAIL_FROM || '').trim())
  };
}

function sanitizeSmtpMessage(message) {
  return String(message || 'SMTP operation failed.')
    .replace(/(password|pass|api[_ -]?key|token|secret|authorization)\s*[:=]?\s*[^\s,;]+/gi, '$1=[redacted]')
    .replace(/\r?\n/g, ' ')
    .slice(0, 300);
}

function logSmtpFailure(prefix, error) {
  console.warn(`${prefix}:`, {
    code: error && error.code ? error.code : undefined,
    command: error && error.command ? error.command : undefined,
    responseCode: error && error.responseCode ? error.responseCode : undefined,
    message: sanitizeSmtpMessage(error && error.message)
  });
}

const otpRequestLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many OTP requests. Please wait a moment and try again.'
  }
});

const otpVerificationLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: 'Too many verification attempts. Please try again shortly.'
  }
});

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname), { index: 'index.html', extensions: ['html'] }));
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error('Origin not allowed by CORS policy'));
    },
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type'],
    credentials: false
  })
);
app.options('*', cors());

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || ''));
}

function createChallengeToken() {
  return crypto.randomBytes(32).toString('hex');
}

function invalidatePreviousChallenge(emailKey) {
  const existingToken = emailChallengeMap.get(emailKey);

  if (!existingToken) {
    return;
  }

  const previousRecord = activeChallenges.get(existingToken);
  if (previousRecord && !previousRecord.used && !previousRecord.invalidated) {
    previousRecord.invalidated = true;
  }

  activeChallenges.delete(existingToken);
  emailChallengeMap.delete(emailKey);
}

async function createEmailTransport() {
  const config = getSmtpConfig();

  return nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: config.auth
  });
}

let cachedTransport = null;

async function getEmailTransport() {
  if (!cachedTransport) {
    cachedTransport = await createEmailTransport();
  }

  return cachedTransport;
}

async function sendOtpEmail(email, otpValue) {
  const transporter = await getEmailTransport();
  const config = getSmtpConfig();
  const senderAddress = config.from;

  const info = await transporter.sendMail({
    from: senderAddress,
    to: email,
    subject: `${APP_NAME} verification code`,
    text: `Your secure verification code is ${otpValue}. This code expires in 5 minutes. Do not share this code with anyone.`
  });

  if (info && info.messageId) {
    console.info('SMTP provider configured: Resend');
  }

  return info;
}

async function verifySmtpConnection() {
  const diagnostics = getSmtpDiagnostics();
  console.info('SMTP host configured:', diagnostics.hostConfigured ? 'yes' : 'no');
  console.info('SMTP port configured:', diagnostics.portConfigured ? 'yes' : 'no');
  console.info('SMTP username configured:', diagnostics.usernameConfigured ? 'yes' : 'no');
  console.info('SMTP password configured:', diagnostics.passwordConfigured ? 'yes' : 'no');
  console.info('EMAIL_FROM configured:', diagnostics.fromConfigured ? 'yes' : 'no');

  try {
    const transporter = await getEmailTransport();
    await transporter.verify();
    console.info('SMTP connection verified successfully');
  } catch (error) {
    logSmtpFailure('SMTP verification failed', error);
  }
}

function buildChallengeRecord(email, userId) {
  const now = Date.now();
  const otpValue = generateSixDigitOtp();
  const challengeToken = createChallengeToken();
  const record = {
    email,
    userId: userId || null,
    otpHash: hashOtp(otpValue),
    challengeToken,
    createdAt: now,
    expiresAt: now + OTP_TTL_MS,
    attemptsUsed: 0,
    maxAttempts: OTP_ATTEMPT_LIMIT,
    used: false,
    invalidated: false,
    lastGeneratedAt: now
  };

  return { challengeToken, otpValue, record };
}

async function issueChallenge(email, userId) {
  const emailKey = normalizeEmail(email);

  if (!isValidEmail(emailKey)) {
    const error = new Error('Please enter a valid email address.');
    error.statusCode = 400;
    throw error;
  }

  const now = Date.now();
  const lastRequestTime = requestCooldowns.get(emailKey) || 0;
  const remainingCooldown = RESEND_COOLDOWN_MS - (now - lastRequestTime);

  if (now - lastRequestTime < RESEND_COOLDOWN_MS) {
    const error = new Error('Too many OTP requests. Please wait a moment and try again.');
    error.statusCode = 429;
    error.retrySeconds = Math.max(1, Math.ceil(remainingCooldown / 1000));
    throw error;
  }

  invalidatePreviousChallenge(emailKey);

  const { challengeToken, otpValue, record } = buildChallengeRecord(emailKey, userId || null);
  activeChallenges.set(challengeToken, record);
  emailChallengeMap.set(emailKey, challengeToken);
  requestCooldowns.set(emailKey, now);

  try {
    await sendOtpEmail(emailKey, otpValue);
  } catch (error) {
    activeChallenges.delete(challengeToken);
    emailChallengeMap.delete(emailKey);
    throw Object.assign(new Error('Email delivery failed. Please try again later.'), {
      statusCode: 503,
      cause: error
    });
  }

  return {
    challengeToken,
    expiresInSeconds: Math.floor(OTP_TTL_MS / 1000)
  };
}

function compareOtpHash(record, submittedOtp) {
  if (!record || !submittedOtp) {
    return false;
  }

  const storedHash = String(record.otpHash || '');
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

app.get('/health', (_req, res) => {
  res.json({ success: true, message: 'OTP backend is running.' });
});

app.post('/api/otp/request', otpRequestLimiter, async (req, res) => {
  try {
    const { email, userId } = req.body || {};
    console.info('OTP request received.');

    const result = await issueChallenge(email, userId || null);
    res.status(200).json({
      success: true,
      message: 'OTP sent successfully.',
      challengeToken: result.challengeToken,
      expiresInSeconds: result.expiresInSeconds
    });
  } catch (error) {
    logSmtpFailure('OTP request failed', error.cause || error);
    const statusCode = Number(error.statusCode || 500);
    const safeMessage = error.message || 'Unable to start MFA verification right now.';
    res.status(statusCode).json({
      success: false,
      message: safeMessage
    });
  }
});

app.post('/api/otp/verify', otpVerificationLimiter, async (req, res) => {
  try {
    const { email, otp, challengeToken, userId } = req.body || {};
    const emailKey = normalizeEmail(email);
    const otpCode = String(otp || '').trim();

    if (!emailKey || !isValidEmail(emailKey)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    if (!otpCode || otpCode.length !== 6 || !/^\d{6}$/.test(otpCode)) {
      return res.status(400).json({ success: false, message: 'Please enter a valid 6-digit OTP.' });
    }

    if (!challengeToken) {
      return res.status(400).json({ success: false, message: 'OTP verification challenge is missing.' });
    }

    const record = activeChallenges.get(challengeToken);

    if (!record || record.email !== emailKey) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
    }

    if (record.userId && userId && record.userId !== userId) {
      record.invalidated = true;
      activeChallenges.delete(challengeToken);
      emailChallengeMap.delete(emailKey);
      return res.status(400).json({ success: false, message: 'OTP challenge does not match this account.' });
    }

    if (record.used || record.invalidated) {
      return res.status(400).json({ success: false, message: 'This OTP has already been used or invalidated.' });
    }

    if (Date.now() > record.expiresAt) {
      record.invalidated = true;
      activeChallenges.delete(challengeToken);
      emailChallengeMap.delete(emailKey);
      return res.status(400).json({ success: false, message: 'OTP expired. Please request a new code.' });
    }

    if (compareOtpHash(record, otpCode)) {
      record.used = true;
      record.userId = userId || record.userId;
      activeChallenges.delete(challengeToken);
      emailChallengeMap.delete(emailKey);

      return res.status(200).json({
        success: true,
        message: 'OTP verified successfully.',
        challengeToken
      });
    }

    record.attemptsUsed += 1;

    if (record.attemptsUsed >= record.maxAttempts) {
      record.invalidated = true;
      activeChallenges.delete(challengeToken);
      emailChallengeMap.delete(emailKey);
      return res.status(400).json({
        success: false,
        message: 'Maximum OTP attempts exceeded. Please request a new code.'
      });
    }

    return res.status(400).json({
      success: false,
      message: 'Invalid OTP. Please try again.'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Verification failed. Please try again.'
    });
  }
});

app.post('/api/otp/resend', otpRequestLimiter, async (req, res) => {
  try {
    const { email, userId, challengeToken } = req.body || {};
    const emailKey = normalizeEmail(email);

    if (!emailKey || !isValidEmail(emailKey)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }

    if (challengeToken) {
      const existingRecord = activeChallenges.get(challengeToken);
      if (existingRecord && existingRecord.email === emailKey) {
        existingRecord.invalidated = true;
        activeChallenges.delete(challengeToken);
        emailChallengeMap.delete(emailKey);
      }
    }

    const result = await issueChallenge(emailKey, userId || null);

    res.status(200).json({
      success: true,
      message: 'A new OTP has been sent.',
      challengeToken: result.challengeToken,
      expiresInSeconds: result.expiresInSeconds
    });
  } catch (error) {
    const statusCode = Number(error.statusCode || 500);
    const safeMessage = error.message || 'Unable to resend OTP right now.';
    res.status(statusCode).json({ success: false, message: safeMessage });
  }
});

app.use((error, _req, res, _next) => {
  if (error && error.message === 'Origin not allowed by CORS policy') {
    return res.status(403).json({ success: false, message: 'This origin is not allowed.' });
  }

  return res.status(500).json({ success: false, message: 'Internal server error.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.info(`OTP backend running on http://0.0.0.0:${PORT}`);
  void verifySmtpConnection();
});
