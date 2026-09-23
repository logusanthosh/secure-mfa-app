const otpManager = {
  COOLDOWN_SECONDS: 60,
  RESEND_LIMIT_SECONDS: 60,
  cooldownTimer: null,

  getCurrentEmail() {
    return sessionStorage.getItem('pendingMfaEmail') || '';
  },

  getChallengeToken() {
    return sessionStorage.getItem('otpChallengeToken') || '';
  },

  maskEmail(email) {
    if (!email || !email.includes('@')) {
      return email || 'your email';
    }

    const [localPart, domain] = email.split('@');
    const visibleLocal = localPart.length <= 2 ? localPart : `${localPart.slice(0, 2)}***`;
    return `${visibleLocal}@${domain}`;
  },

  getRemainingCooldownSeconds() {
    const cooldownUntil = Number(sessionStorage.getItem('otpCooldownUntil') || 0);

    if (!cooldownUntil) {
      return 0;
    }

    return Math.max(0, Math.ceil((cooldownUntil - Date.now()) / 1000));
  },

  formatCooldown(seconds) {
    const safeSeconds = Math.max(0, seconds);
    const mins = String(Math.floor(safeSeconds / 60)).padStart(2, '0');
    const secs = String(safeSeconds % 60).padStart(2, '0');
    return `${mins}:${secs}`;
  },

  setStatus(elementId, type, message) {
    const element = document.getElementById(elementId);
    if (!element) {
      return;
    }

    element.className = `alert alert-${type} auth-alert visible`;
    element.textContent = message;
  },

  setCooldownButton(button, remainingSeconds) {
    if (!button) {
      return;
    }

    const isCoolingDown = remainingSeconds > 0;
    button.disabled = isCoolingDown;
    button.textContent = isCoolingDown ? `Resend available in ${remainingSeconds}s` : 'Resend Code';
  },

  clearCooldownTimer() {
    if (this.cooldownTimer) {
      clearInterval(this.cooldownTimer);
      this.cooldownTimer = null;
    }
  },

  startCooldown(button) {
    const remainingSeconds = this.getRemainingCooldownSeconds();

    this.clearCooldownTimer();
    this.setCooldownButton(button, remainingSeconds);

    if (remainingSeconds <= 0) {
      return;
    }

    this.cooldownTimer = setInterval(() => {
      const nextRemainingSeconds = this.getRemainingCooldownSeconds();
      this.setCooldownButton(button, nextRemainingSeconds);

      if (nextRemainingSeconds <= 0) {
        this.clearCooldownTimer();
        this.setCooldownButton(button, 0);
      }
    }, 1000);
  }
};

document.addEventListener('DOMContentLoaded', () => {
  authManager.init();

  const otpEmail = document.getElementById('otpEmail');
  const otpForm = document.getElementById('otpForm');
  const otpCodeInput = document.getElementById('otpCode');
  const resendOtpButton = document.getElementById('resendOtpButton');
  const verifyOtpButton = document.getElementById('verifyOtpButton');

  if (otpEmail) {
    const currentEmail = otpManager.getCurrentEmail();
    otpEmail.value = currentEmail;
    otpEmail.setAttribute('aria-label', 'Email address');
  }

  if (resendOtpButton) {
    const remainingSeconds = otpManager.getRemainingCooldownSeconds();
    otpManager.setCooldownButton(resendOtpButton, remainingSeconds);

    if (remainingSeconds > 0) {
      otpManager.startCooldown(resendOtpButton);
    }

    resendOtpButton.addEventListener('click', async () => {
      const email = otpManager.getCurrentEmail();
      if (!email) {
        otpManager.setStatus('otpError', 'danger', 'No active verification request was found. Please log in again.');
        return;
      }

      try {
        otpManager.setStatus('otpSuccess', 'success', 'Requesting a new OTP...');
        await authManager.resendMfaOtp(email);
        otpManager.setStatus('otpSuccess', 'success', 'A new OTP has been sent to your email.');
        otpManager.startCooldown(resendOtpButton);
      } catch (error) {
        otpManager.setStatus('otpError', 'danger', error.message || 'Unable to resend OTP.');
      }
    });
  }

  if (otpForm) {
    otpForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const email = otpManager.getCurrentEmail();
      const otp = otpCodeInput ? otpCodeInput.value.trim() : '';

      if (!email) {
        otpManager.setStatus('otpError', 'danger', 'Your email is missing. Please log in again.');
        return;
      }

      if (verifyOtpButton) {
        verifyOtpButton.disabled = true;
        verifyOtpButton.textContent = 'Verifying...';
      }

      try {
        otpManager.setStatus('otpError', 'danger', '');
        otpManager.setStatus('otpSuccess', 'success', 'Verifying your OTP...');
        await authManager.verifyMfaOtp(email, otp);
        otpManager.setStatus('otpSuccess', 'success', 'OTP verified successfully. Redirecting to your dashboard...');
        setTimeout(() => {
          window.location.href = 'dashboard.html';
        }, 800);
      } catch (error) {
        otpManager.setStatus('otpSuccess', 'success', '');
        otpManager.setStatus('otpError', 'danger', error.message || 'Verification failed.');
      } finally {
        if (verifyOtpButton) {
          verifyOtpButton.disabled = false;
          verifyOtpButton.textContent = 'Verify OTP';
        }
      }
    });
  }

  if (otpCodeInput) {
    otpCodeInput.addEventListener('input', () => {
      otpCodeInput.value = otpCodeInput.value.replace(/\D/g, '').slice(0, 6);
    });
  }
});
