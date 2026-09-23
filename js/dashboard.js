document.addEventListener('DOMContentLoaded', () => {
  authManager.init();

  const logoutButton = document.getElementById('logoutButton');
  if (logoutButton) {
    logoutButton.addEventListener('click', async () => {
      try {
        await authManager.logout();
      } catch (error) {
        console.error('Logout failed:', error);
      }
    });
  }

  authManager.attachAuthStateListener((user) => {
    const nameElement = document.getElementById('userName');
    const emailElement = document.getElementById('userEmail');
    const providerElement = document.getElementById('authProvider');
    const mfaStatusElement = document.getElementById('mfaStatus');

    if (!user) {
      if (nameElement) {
        nameElement.textContent = 'Not signed in';
      }
      if (emailElement) {
        emailElement.textContent = 'Please sign in';
      }
      if (providerElement) {
        providerElement.textContent = 'Unavailable';
      }
      if (mfaStatusElement) {
        mfaStatusElement.textContent = 'Access denied';
      }
      return;
    }

    const displayName = user.displayName || 'User';
    const email = user.email || 'Not available';
    const provider = user.providerData && user.providerData.length ? user.providerData[0].providerId : 'password';
    const hasGoogleProvider = user.providerData && user.providerData.some((item) => item.providerId === 'google.com');
    const isMfaVerified = hasGoogleProvider || sessionStorage.getItem('mfaVerified') === 'true';

    if (nameElement) {
      nameElement.textContent = displayName;
    }

    if (emailElement) {
      emailElement.textContent = email;
    }

    if (providerElement) {
      const readableProvider = provider === 'password' ? 'Email + Password' : provider === 'google.com' ? 'Google' : provider;
      providerElement.textContent = readableProvider;
    }

    if (mfaStatusElement) {
      mfaStatusElement.textContent = isMfaVerified ? 'MFA verified' : 'MFA pending';
      mfaStatusElement.className = isMfaVerified ? 'text-success fw-semibold' : 'text-warning fw-semibold';
    }

    if (!hasGoogleProvider && !isMfaVerified) {
      sessionStorage.setItem('pendingMfaEmail', user.email || '');
      window.location.href = 'verify-otp.html';
    }
  });
});
