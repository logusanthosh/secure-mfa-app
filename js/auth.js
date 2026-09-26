const authManager = {
  app: null,
  auth: null,
  initialized: false,
  authStateListenerAttached: false,
  stateCallbacks: [],

  init() {
    if (this.initialized) {
      return this.auth;
    }

    if (typeof firebase === 'undefined') {
      console.error('Firebase SDK is not loaded. Make sure the Firebase scripts are included before auth.js.');
      return null;
    }

    this.app = firebase.apps.length ? firebase.app() : firebase.initializeApp(firebaseConfig);
    this.auth = firebase.auth();
    this.initialized = true;

    this.attachAuthStateListener();
    return this.auth;
  },

  attachAuthStateListener(callback) {
    if (typeof callback === 'function') {
      this.stateCallbacks.push(callback);
    }

    if (!this.auth) {
      return;
    }

    if (this.authStateListenerAttached) {
      return;
    }

    this.authStateListenerAttached = true;

    this.auth.onAuthStateChanged((user) => {
      const currentPage = window.location.pathname.split('/').pop() || 'index.html';

      this.stateCallbacks.forEach((listener) => {
        try {
          listener(user);
        } catch (error) {
          console.error('Auth state callback failed:', error);
        }
      });

      if ((currentPage === 'login.html' || currentPage === 'register.html' || currentPage === 'index.html') && user) {
        const hasGoogleProvider = user.providerData && user.providerData.some((provider) => provider.providerId === 'google.com');
        const isOtpVerified = sessionStorage.getItem('mfaVerified') === 'true';

        if (hasGoogleProvider || isOtpVerified) {
          window.location.href = 'dashboard.html';
        }
      }

      if (currentPage === 'dashboard.html' && !user) {
        window.location.href = 'login.html';
      }

      if (currentPage === 'dashboard.html' && user) {
        const hasGoogleProvider = user.providerData && user.providerData.some((provider) => provider.providerId === 'google.com');

        if (!hasGoogleProvider && sessionStorage.getItem('mfaVerified') !== 'true') {
          sessionStorage.setItem('pendingMfaEmail', user.email || '');
          window.location.href = 'verify-otp.html';
        }
      }
    });
  },

  getCurrentUser() {
    return this.auth ? this.auth.currentUser : null;
  },

  requireAuth() {
    if (!this.auth) {
      throw new Error('Firebase authentication is not available. Please configure firebase-config.js with your Firebase settings.');
    }
  },

  async requestMfaOtp(email) {
    const targetEmail = (email || '').trim();

    if (!targetEmail) {
      throw new Error('Email is required before starting MFA verification.');
    }

    const currentUser = this.getCurrentUser();
    const userId = currentUser && currentUser.uid ? currentUser.uid : '';
    const apiUrl = this.getOtpApiBaseUrl();
    console.info('OTP request started.');

    let response;
    try {
      response = await fetch(`${apiUrl}/api/otp/request`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ email: targetEmail, userId })
      });
    } catch (_error) {
      const networkError = new Error('The OTP service could not be reached. Please make sure the backend is running on http://localhost:3000.');
      networkError.isOtpRequestError = true;
      throw networkError;
    }

    const data = await response.json().catch(() => ({}));
    console.info(`OTP request backend response: ${response.status}.`);

    if (!response.ok) {
      const requestError = new Error(data.message || 'Unable to start MFA verification right now.');
      requestError.isOtpRequestError = true;
      throw requestError;
    }

    sessionStorage.setItem('pendingMfaEmail', targetEmail);
    if (data.challengeToken) {
      sessionStorage.setItem('otpChallengeToken', data.challengeToken);
    }
    sessionStorage.setItem('otpCooldownUntil', String(Date.now() + 60000));
    return data;
  },

  getOtpApiBaseUrl() {
    if (window.OTP_API_BASE_URL) {
      return String(window.OTP_API_BASE_URL).replace(/\/$/, '');
    }

    const defaultBaseUrl = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'http://localhost:3000'
      : 'https://secure-mfa-app.onrender.com';

    return defaultBaseUrl.replace(/\/$/, '');
  },

  async verifyMfaOtp(email, otp) {
    const targetEmail = (email || '').trim();
    const otpCode = (otp || '').trim();

    if (!targetEmail) {
      throw new Error('Email is required for OTP verification.');
    }

    if (!otpCode || otpCode.length !== 6) {
      throw new Error('Please enter a valid 6-digit code.');
    }

    const currentUser = this.getCurrentUser();
    const userId = currentUser && currentUser.uid ? currentUser.uid : '';
    const challengeToken = sessionStorage.getItem('otpChallengeToken') || '';
    const apiUrl = this.getOtpApiBaseUrl();
    const response = await fetch(`${apiUrl}/api/otp/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email: targetEmail, otp: otpCode, userId, challengeToken })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.message || 'OTP verification failed.');
    }

    sessionStorage.setItem('mfaVerified', 'true');
    sessionStorage.setItem('pendingMfaEmail', targetEmail);
    sessionStorage.setItem('otpChallengeToken', data.challengeToken || challengeToken);
    sessionStorage.removeItem('pendingRegistrationEmail');
    sessionStorage.removeItem('otpCooldownUntil');
    return data;
  },

  async resendMfaOtp(email) {
    const targetEmail = (email || '').trim();

    if (!targetEmail) {
      throw new Error('Email is required before resending the OTP.');
    }

    const currentUser = this.getCurrentUser();
    const userId = currentUser && currentUser.uid ? currentUser.uid : '';
    const challengeToken = sessionStorage.getItem('otpChallengeToken') || '';
    const apiUrl = this.getOtpApiBaseUrl();
    const response = await fetch(`${apiUrl}/api/otp/resend`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ email: targetEmail, userId, challengeToken })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(data.message || 'Unable to resend the OTP right now.');
    }

    if (data.challengeToken) {
      sessionStorage.setItem('otpChallengeToken', data.challengeToken);
    }
    sessionStorage.setItem('otpCooldownUntil', String(Date.now() + 60000));

    return data;
  },

  async registerWithEmailAndPassword(name, email, password) {
    this.requireAuth();

    const cleanedName = (name || '').trim();

    if (!cleanedName) {
      throw new Error('Please enter your full name.');
    }

    if (!email || !password) {
      throw new Error('Email and password are required.');
    }

    const credentials = await this.auth.createUserWithEmailAndPassword(email, password);

    if (credentials.user && cleanedName) {
      await credentials.user.updateProfile({
        displayName: cleanedName
      });
    }

    return credentials.user;
  },

  async loginWithEmailAndPassword(email, password) {
    this.requireAuth();

    if (!email || !password) {
      throw new Error('Email and password are required.');
    }

    const credentials = await this.auth.signInWithEmailAndPassword(email, password);
    return credentials.user;
  },

  async signInWithGoogle() {
    this.requireAuth();

    const provider = new firebase.auth.GoogleAuthProvider();
    const credentials = await this.auth.signInWithPopup(provider);
    sessionStorage.setItem('mfaVerified', 'true');
    return credentials.user;
  },

  async resetPassword(email) {
    this.requireAuth();

    if (!email) {
      throw new Error('Please enter your email address.');
    }

    await this.auth.sendPasswordResetEmail(email);
    return true;
  },

  async logout() {
    this.requireAuth();
    sessionStorage.removeItem('mfaVerified');
    sessionStorage.removeItem('pendingMfaEmail');
    sessionStorage.removeItem('otpChallengeToken');
    sessionStorage.removeItem('otpCooldownUntil');
    sessionStorage.removeItem('pendingRegistrationEmail');
    await this.auth.signOut();
    return true;
  }
};

function formatFirebaseError(error) {
  if (!error || !error.code) {
    return 'Something went wrong. Please try again.';
  }

  const messages = {
    'auth/invalid-email': 'Please enter a valid email address.',
    'auth/user-disabled': 'This account has been disabled. Please contact support.',
    'auth/user-not-found': 'No account was found with this email.',
    'auth/wrong-password': 'Incorrect password. Please try again.',
    'auth/email-already-in-use': 'This email is already registered. Please log in instead.',
    'auth/weak-password': 'Your password is too weak. Use at least 6 characters.',
    'auth/too-many-requests': 'Too many attempts. Please wait a moment and try again.',
    'auth/popup-closed-by-user': 'Google sign-in was cancelled.',
    'auth/network-request-failed': 'Network error. Please check your internet connection and try again.',
    'auth/requires-recent-login': 'Please log in again before continuing.',
    'auth/cancelled-popup-request': 'The Google sign-in popup was cancelled.',
    'auth/popup-blocked': 'The Google sign-in popup was blocked. Please allow popups and try again.'
  };

  return messages[error.code] || 'Something went wrong. Please try again.';
}

function setAlert(elementId, type, message) {
  const element = document.getElementById(elementId);

  if (!element) {
    return;
  }

  element.className = `alert alert-${type} auth-alert visible`;
  element.textContent = message;
}

document.addEventListener('DOMContentLoaded', () => {
  authManager.init();

  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    const loginButton = document.getElementById('loginButton');

    loginForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const email = document.getElementById('loginEmail').value.trim();
      const password = document.getElementById('loginPassword').value.trim();

      if (loginButton) {
        loginButton.disabled = true;
        loginButton.textContent = 'Signing in...';
      }

      try {
        setAlert('loginMessage', 'info', 'Signing you in...');
        const user = await authManager.loginWithEmailAndPassword(email, password);

        if (user && user.email) {
          await authManager.requestMfaOtp(user.email);
          sessionStorage.setItem('pendingMfaEmail', user.email);
          window.location.href = 'verify-otp.html';
        }
      } catch (error) {
        setAlert('loginMessage', 'danger', formatFirebaseError(error));
      } finally {
        if (loginButton) {
          loginButton.disabled = false;
          loginButton.textContent = 'Sign in';
        }
      }
    });
  }

  const registerForm = document.getElementById('registerForm');
  if (registerForm) {
    const registerButton = document.getElementById('registerButton');

    registerForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      const name = document.getElementById('registerName').value.trim();
      const email = document.getElementById('registerEmail').value.trim();
      const password = document.getElementById('registerPassword').value;
      const confirmPassword = document.getElementById('confirmPassword').value;

      if (!name || !email || !password || !confirmPassword) {
        setAlert('registerMessage', 'danger', 'Please complete all fields.');
        return;
      }

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        setAlert('registerMessage', 'danger', 'Please enter a valid email address.');
        return;
      }

      if (password.length < 6) {
        setAlert('registerMessage', 'danger', 'Your password is too weak. Use at least 6 characters.');
        return;
      }

      if (password !== confirmPassword) {
        setAlert('registerMessage', 'danger', 'Passwords do not match.');
        return;
      }

      if (registerButton) {
        registerButton.disabled = true;
        registerButton.textContent = 'Creating account...';
      }

      const normalizedEmail = email.toLowerCase();
      const pendingRegistrationEmail = sessionStorage.getItem('pendingRegistrationEmail') || '';
      const hasPendingRegistration = pendingRegistrationEmail === normalizedEmail;
      let accountCreated = false;

      try {
        let user = authManager.getCurrentUser();

        if (hasPendingRegistration) {
          if (!user || (user.email || '').toLowerCase() !== normalizedEmail) {
            throw new Error('Your account is still loading. Please wait a moment and try again.');
          }
          accountCreated = true;
        } else {
          setAlert('registerMessage', 'info', 'Creating your account...');
          user = await authManager.registerWithEmailAndPassword(name, email, password);
          accountCreated = true;
          sessionStorage.setItem('pendingRegistrationEmail', normalizedEmail);
        }

        if (!user || !user.email) {
          throw new Error('Account creation did not complete. Please try again.');
        }

        setAlert('registerMessage', 'info', accountCreated ? 'Account created. Sending your verification code...' : 'Sending your verification code...');
        await authManager.requestMfaOtp(user.email);
        setAlert('registerMessage', 'success', 'Account created. Verification code sent.');
        window.location.href = 'verify-otp.html';
      } catch (error) {
        const message = accountCreated && !error.isOtpRequestError
          ? 'Account created, but we could not send the verification code. Please try again.'
          : accountCreated
            ? error.message
            : formatFirebaseError(error);
        setAlert('registerMessage', 'danger', message);
      } finally {
        if (registerButton) {
          registerButton.disabled = false;
          registerButton.textContent = 'Register';
        }
      }
    });
  }

  const googleButtons = document.querySelectorAll('[data-google-auth]');
  googleButtons.forEach((button) => {
    button.addEventListener('click', async () => {
      const messageId = button.dataset.messageId || 'loginMessage';

      try {
        setAlert(messageId, 'info', 'Connecting to Google...');
        await authManager.signInWithGoogle();
      } catch (error) {
        setAlert(messageId, 'danger', formatFirebaseError(error));
      }
    });
  });

  const forgotPasswordLink = document.getElementById('forgotPasswordLink');
  if (forgotPasswordLink) {
    forgotPasswordLink.addEventListener('click', async (event) => {
      event.preventDefault();

      const email = document.getElementById('loginEmail').value.trim();
      if (!email) {
        setAlert('loginMessage', 'warning', 'Enter your email first so we can send a reset link.');
        return;
      }

      try {
        setAlert('loginMessage', 'info', 'Sending password reset email...');
        await authManager.resetPassword(email);
        setAlert('loginMessage', 'success', 'A password reset email has been sent. Check your inbox.');
      } catch (error) {
        setAlert('loginMessage', 'danger', formatFirebaseError(error));
      }
    });
  }

  const passwordToggles = document.querySelectorAll('[data-password-toggle]');
  passwordToggles.forEach((toggle) => {
    toggle.addEventListener('click', () => {
      const target = document.getElementById(toggle.dataset.target);
      if (!target) {
        return;
      }

      const isVisible = target.type === 'text';
      target.type = isVisible ? 'password' : 'text';
      toggle.setAttribute('aria-label', isVisible ? 'Show password' : 'Hide password');
      toggle.setAttribute('aria-pressed', String(!isVisible));
    });
  });

  const registerPassword = document.getElementById('registerPassword');
  const passwordStrengthBar = document.getElementById('passwordStrengthBar');
  const passwordStrengthText = document.getElementById('passwordStrengthText');
  const confirmPassword = document.getElementById('confirmPassword');

  function updatePasswordStrength() {
    if (!registerPassword || !passwordStrengthBar || !passwordStrengthText) {
      return;
    }

    const password = registerPassword.value;
    let strength = 0;
    if (password.length >= 6) strength += 1;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) strength += 1;
    if (/\d/.test(password) || /[^A-Za-z0-9]/.test(password)) strength += 1;

    const labels = ['Use at least 6 characters.', 'Basic strength', 'Good strength', 'Strong password'];
    const colors = ['var(--danger-color)', 'var(--danger-color)', 'var(--warning-color)', 'var(--success-color)'];
    passwordStrengthBar.style.width = `${Math.min(100, strength * 33.333)}%`;
    passwordStrengthBar.style.background = colors[strength];
    passwordStrengthText.textContent = labels[strength];
  }

  function validatePasswordMatch() {
    if (!confirmPassword || !registerPassword || !confirmPassword.value) {
      return;
    }

    const matches = confirmPassword.value === registerPassword.value;
    confirmPassword.setCustomValidity(matches ? '' : 'Passwords do not match.');
    confirmPassword.classList.toggle('is-invalid', !matches);
    confirmPassword.classList.toggle('is-valid', matches);
  }

  if (registerPassword) {
    registerPassword.addEventListener('input', () => {
      updatePasswordStrength();
      validatePasswordMatch();
    });
    updatePasswordStrength();
  }

  if (confirmPassword) {
    confirmPassword.addEventListener('input', validatePasswordMatch);
  }
});
