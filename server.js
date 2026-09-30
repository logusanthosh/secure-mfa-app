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

app.set('trust proxy', 1);

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

/* =========================================================
   EMAIL CONFIGURATION - GMAIL SMTP
   ========================================================= */

const smtpTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT || 465),
  secure: process.env.EMAIL_SECURE !== 'false',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

function isSmtpConfigured() {
  return Boolean(
    String(process.env.EMAIL_HOST || '').trim() &&
    String(process.env.EMAIL_USER || '').trim() &&
    String(process.env.EMAIL_PASSWORD || '').trim() &&
    String(process.env.EMAIL_FROM || '').trim()
  );
}

function getEmailConfig() {
  const from = String(process.env.EMAIL_FROM || '').trim();

  if (!isSmtpConfigured()) {
    const error = new Error('SMTP configuration is incomplete.');
    error.statusCode = 503;
    throw error;
  }

  return { from };
}

function logSmtpFailure(prefix, error) {
  console.error(`${prefix}:`, {
    name: error?.name,
    code: error?.code,
    responseCode: error?.responseCode
  });
}

/* =========================================================
   RATE LIMITERS
   ========================================================= */

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

const otpResendLimiter = rateLimit({
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

/* =========================================================
   MIDDLEWARE
   ========================================================= */

app.use(express.json({ limit: '1mb' }));

app.use(
  express.static(path.join(__dirname), {
    index: 'index.html',
    extensions: ['html']
  })
);

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
    exposedHeaders: [
      'Retry-After',
      'RateLimit-Limit',
      'RateLimit-Remaining',
      'RateLimit-Reset',
      'RateLimit-Policy'
    ],
    credentials: false
  })
);

app.options('*', cors());

/* =========================================================
   HELPERS
   ========================================================= */

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

  if (
    previousRecord &&
    !previousRecord.used &&
    !previousRecord.invalidated
  ) {
    previousRecord.invalidated = true;
  }

  activeChallenges.delete(existingToken);
  emailChallengeMap.delete(emailKey);
}

/* =========================================================
   SEND OTP EMAIL
   ========================================================= */

async function sendOtpEmail(email, otpValue) {
  const config = getEmailConfig();

  return smtpTransporter.sendMail({
    from: config.from,
    to: email,
    subject: `${APP_NAME} verification code`,
    text:
      `Your secure verification code is ${otpValue}. ` +
      `This code expires in 5 minutes. ` +
      `Do not share this code with anyone.`
  });
}

/* =========================================================
   OTP CHALLENGE
   ========================================================= */

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

  return {
    challengeToken,
    otpValue,
    record
  };
}

async function issueChallenge(email, userId) {
  const emailKey = normalizeEmail(email);

  if (!isValidEmail(emailKey)) {
    const error = new Error(
      'Please enter a valid email address.'
    );

    error.statusCode = 400;

    throw error;
  }

  const now = Date.now();

  const lastRequestTime =
    requestCooldowns.get(emailKey) || 0;

  const remainingCooldown =
    RESEND_COOLDOWN_MS -
    (now - lastRequestTime);

  if (
    now - lastRequestTime <
    RESEND_COOLDOWN_MS
  ) {
    const error = new Error(
      'Too many OTP requests. Please wait a moment and try again.'
    );

    error.statusCode = 429;

    error.retrySeconds = Math.max(
      1,
      Math.ceil(remainingCooldown / 1000)
    );

    throw error;
  }

  invalidatePreviousChallenge(emailKey);

  const {
    challengeToken,
    otpValue,
    record
  } = buildChallengeRecord(
    emailKey,
    userId || null
  );

  activeChallenges.set(
    challengeToken,
    record
  );

  emailChallengeMap.set(
    emailKey,
    challengeToken
  );

  try {
    await sendOtpEmail(
      emailKey,
      otpValue
    );

    requestCooldowns.set(
      emailKey,
      now
    );
  } catch (error) {
    activeChallenges.delete(
      challengeToken
    );

    emailChallengeMap.delete(
      emailKey
    );

    logSmtpFailure(
      'SMTP email send failed',
      error
    );

    throw Object.assign(
      new Error(
        'Email delivery failed. Please try again later.'
      ),
      {
        statusCode: 503,
        cause: error
      }
    );
  }

  return {
    challengeToken,

    expiresInSeconds:
      Math.floor(
        OTP_TTL_MS / 1000
      )
  };
}

/* =========================================================
   OTP HASH COMPARISON
   ========================================================= */

function compareOtpHash(
  record,
  submittedOtp
) {
  if (!record || !submittedOtp) {
    return false;
  }

  const storedHash =
    String(record.otpHash || '');

  const submittedHash =
    hashOtp(
      String(submittedOtp)
    );

  try {
    return crypto.timingSafeEqual(
      Buffer.from(
        storedHash,
        'hex'
      ),
      Buffer.from(
        submittedHash,
        'hex'
      )
    );
  } catch (_error) {
    return false;
  }
}

/* =========================================================
   HEALTH CHECK
   ========================================================= */

app.get('/health', (_req, res) => {
  res.json({
    success: true,
    message: 'OTP backend is running.'
  });
});

/* =========================================================
   REQUEST OTP
   ========================================================= */

app.post(
  '/api/otp/request',
  otpRequestLimiter,
  async (req, res) => {
    try {
      const {
        email,
        userId
      } = req.body || {};

      console.info(
        'OTP request received.'
      );

      const result =
        await issueChallenge(
          email,
          userId || null
        );

      res.status(200).json({
        success: true,

        message:
          'OTP sent successfully.',

        challengeToken:
          result.challengeToken,

        expiresInSeconds:
          result.expiresInSeconds
      });
    } catch (error) {
      const statusCode =
        Number(
          error.statusCode || 500
        );

      if (
        statusCode === 429 &&
        error.retrySeconds
      ) {
        res.set(
          'Retry-After',
          String(
            error.retrySeconds
          )
        );
      }

      const safeMessage =
        statusCode === 429
          ? 'Too many OTP requests. Please wait and try again.'
          : statusCode < 500
            ? error.message
            : 'Unable to send an OTP right now. Please try again later.';

      res.status(
        statusCode
      ).json({
        success: false,
        message: safeMessage
      });
    }
  }
);

/* =========================================================
   VERIFY OTP
   ========================================================= */

app.post(
  '/api/otp/verify',
  otpVerificationLimiter,
  async (req, res) => {
    try {
      const {
        email,
        otp,
        challengeToken,
        userId
      } = req.body || {};

      const emailKey =
        normalizeEmail(email);

      const otpCode =
        String(otp || '').trim();

      if (
        !emailKey ||
        !isValidEmail(emailKey)
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Please provide a valid email address.'
        });
      }

      if (
        !otpCode ||
        otpCode.length !== 6 ||
        !/^\d{6}$/.test(otpCode)
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Please enter a valid 6-digit OTP.'
        });
      }

      if (!challengeToken) {
        return res.status(400).json({
          success: false,
          message:
            'OTP verification challenge is missing.'
        });
      }

      const record =
        activeChallenges.get(
          challengeToken
        );

      if (
        !record ||
        record.email !== emailKey
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Invalid or expired OTP.'
        });
      }

      if (
        record.userId &&
        userId &&
        record.userId !== userId
      ) {
        record.invalidated = true;

        activeChallenges.delete(
          challengeToken
        );

        emailChallengeMap.delete(
          emailKey
        );

        return res.status(400).json({
          success: false,
          message:
            'OTP challenge does not match this account.'
        });
      }

      if (
        record.used ||
        record.invalidated
      ) {
        return res.status(400).json({
          success: false,
          message:
            'This OTP has already been used or invalidated.'
        });
      }

      if (
        Date.now() >
        record.expiresAt
      ) {
        record.invalidated = true;

        activeChallenges.delete(
          challengeToken
        );

        emailChallengeMap.delete(
          emailKey
        );

        return res.status(400).json({
          success: false,
          message:
            'OTP expired. Please request a new code.'
        });
      }

      if (
        compareOtpHash(
          record,
          otpCode
        )
      ) {
        record.used = true;

        record.userId =
          userId ||
          record.userId;

        activeChallenges.delete(
          challengeToken
        );

        emailChallengeMap.delete(
          emailKey
        );

        return res.status(200).json({
          success: true,
          message:
            'OTP verified successfully.',
          challengeToken
        });
      }

      record.attemptsUsed += 1;

      if (
        record.attemptsUsed >=
        record.maxAttempts
      ) {
        record.invalidated = true;

        activeChallenges.delete(
          challengeToken
        );

        emailChallengeMap.delete(
          emailKey
        );

        return res.status(400).json({
          success: false,
          message:
            'Maximum OTP attempts exceeded. Please request a new code.'
        });
      }

      return res.status(400).json({
        success: false,
        message:
          'Invalid OTP. Please try again.'
      });
    } catch (_error) {
      res.status(500).json({
        success: false,
        message:
          'Verification failed. Please try again.'
      });
    }
  }
);

/* =========================================================
   RESEND OTP
   ========================================================= */

app.post(
  '/api/otp/resend',
  otpResendLimiter,
  async (req, res) => {
    try {
      const {
        email,
        userId,
        challengeToken
      } = req.body || {};

      const emailKey =
        normalizeEmail(email);

      if (
        !emailKey ||
        !isValidEmail(emailKey)
      ) {
        return res.status(400).json({
          success: false,
          message:
            'Please provide a valid email address.'
        });
      }

      if (challengeToken) {
        const existingRecord =
          activeChallenges.get(
            challengeToken
          );

        if (
          existingRecord &&
          existingRecord.email ===
            emailKey
        ) {
          existingRecord.invalidated =
            true;

          activeChallenges.delete(
            challengeToken
          );

          emailChallengeMap.delete(
            emailKey
          );
        }
      }

      const result =
        await issueChallenge(
          emailKey,
          userId || null
        );

      res.status(200).json({
        success: true,
        message:
          'A new OTP has been sent.',
        challengeToken:
          result.challengeToken,
        expiresInSeconds:
          result.expiresInSeconds
      });
    } catch (error) {
      const statusCode =
        Number(
          error.statusCode || 500
        );

      if (
        statusCode === 429 &&
        error.retrySeconds
      ) {
        res.set(
          'Retry-After',
          String(
            error.retrySeconds
          )
        );
      }

      const safeMessage =
        statusCode === 429
          ? 'Too many OTP requests. Please wait and try again.'
          : statusCode < 500
            ? error.message
            : 'Unable to resend the OTP right now. Please try again later.';

      res.status(
        statusCode
      ).json({
        success: false,
        message: safeMessage
      });
    }
  }
);

/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (
    error,
    _req,
    res,
    _next
  ) => {
    if (
      error &&
      error.message ===
        'Origin not allowed by CORS policy'
    ) {
      return res.status(403).json({
        success: false,
        message:
          'This origin is not allowed.'
      });
    }

    return res.status(500).json({
      success: false,
      message:
        'Internal server error.'
    });
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

app.listen(
  PORT,
  '0.0.0.0',
  () => {
    console.info(
      `OTP backend running on http://0.0.0.0:${PORT}`
    );

    const smtpConfigured = isSmtpConfigured();
    console.info('SMTP configuration complete:', smtpConfigured);

    if (!smtpConfigured) {
      console.info('SMTP connection verified: false');
      return;
    }

    smtpTransporter.verify().then(
      () => {
        console.info('SMTP connection verified: true');
      },
      (error) => {
        logSmtpFailure('SMTP connection verification failed', error);
        console.info('SMTP connection verified: false');
      }
    );
  }
);