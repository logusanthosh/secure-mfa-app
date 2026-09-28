function getProviderIdList(user) {
  if (!user || !user.providerData || !Array.isArray(user.providerData)) {
    return [];
  }

  return user.providerData.map((provider) => provider && provider.providerId ? provider.providerId : '').filter(Boolean);
}

function buildAuthMethodCards(user) {
  const providerIds = getProviderIdList(user);
  const hasEmailPassword = providerIds.includes('password');
  const hasGoogle = providerIds.includes('google.com');
  const isMfaVerified = sessionStorage.getItem('mfaVerified') === 'true';

  const methodDefinitions = [
    {
      key: 'emailPassword',
      icon: '🔐',
      title: 'Email + Password',
      active: hasEmailPassword,
      detail: hasEmailPassword ? 'Authenticated' : 'Not Used',
      subLabel: hasEmailPassword ? 'Primary Authentication' : 'Not Used',
      badge: hasEmailPassword ? 'AUTHENTICATED' : '',
      statusClass: hasEmailPassword ? 'status-positive' : 'status-neutral'
    },
    {
      key: 'otp',
      icon: '✉️',
      title: 'Email OTP',
      active: isMfaVerified,
      detail: isMfaVerified ? 'MFA Verified' : 'Not Required / Not Used',
      subLabel: isMfaVerified ? 'Second-Factor Authentication' : 'Not Required / Not Used',
      badge: isMfaVerified ? 'MFA VERIFIED' : '',
      statusClass: isMfaVerified ? 'status-positive' : 'status-neutral'
    },
    {
      key: 'google',
      icon: '🔵',
      title: 'Google Sign-In',
      active: hasGoogle,
      detail: hasGoogle ? 'Authenticated' : 'Not Used',
      subLabel: hasGoogle ? 'Primary Authentication' : 'Not Used',
      badge: hasGoogle ? 'AUTHENTICATED' : '',
      statusClass: hasGoogle ? 'status-positive' : 'status-neutral'
    }
  ];

  return methodDefinitions.map((method) => ({
    ...method,
    providerUnavailable: !user || providerIds.length === 0
  }));
}

function renderAuthMethodCards(user) {
  const listElement = document.getElementById('authMethodList');

  if (!listElement) {
    return;
  }

  if (!user) {
    listElement.innerHTML = '<div class="auth-method-empty">Authentication method unavailable</div>';
    return;
  }

  const providerIds = getProviderIdList(user);
  const methods = buildAuthMethodCards(user);
  const unavailable = !user || providerIds.length === 0;

  listElement.innerHTML = methods.map((method) => {
    const isActive = method.active && !unavailable;
    const badgeMarkup = method.badge ? `<span class="auth-badge ${isActive ? 'badge-active' : 'badge-inactive'}">${method.badge}</span>` : '';
    const statusMarkup = method.active && !unavailable
      ? `<span class="auth-status ${method.statusClass}">✓ ${method.detail}</span>`
      : `<span class="auth-status ${method.statusClass}">${method.detail}</span>`;

    return `
      <article class="auth-method-card ${isActive ? 'is-active' : ''}" data-method="${method.key}">
        <div class="auth-method-header">
          <div class="auth-method-icon" aria-hidden="true">${method.icon}</div>
          <div class="auth-method-copy">
            <h3>${method.title}</h3>
            <p>${method.subLabel}</p>
          </div>
        </div>
        <div class="auth-method-row">
          ${badgeMarkup}
          ${statusMarkup}
        </div>
      </article>
    `;
  }).join('');
}

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
      renderAuthMethodCards(null);
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

    renderAuthMethodCards(user);

    if (!hasGoogleProvider && !isMfaVerified) {
      sessionStorage.setItem('pendingMfaEmail', user.email || '');
      window.location.href = 'verify-otp.html';
    }
  });
});
