/**
 * PhishGuard Extension - UI State Controller
 * Manages Safe and Phishing states within the single panel layout.
 */

(function () {
  'use strict';

  const STATES = {
    SAFE: 'safe',
    PHISHING: 'phishing',
  };

  const STATE_DATA = {
    [STATES.PHISHING]: {
      pageTitle: 'PhishGuard – Phishing Detected',
      url: 'https://secure-login.paypal-verification-update.com/login',
      headerSubtitle: '⚠️ Threat Warning: Phishing Detected',
      statusClass: 'status-phishing',
      statusTitle: 'PHISHING DETECTED',
      statusDetail: 'Deceptive site identified attempting to steal credentials.',
      statusIcon: `
        <svg class="status-icon status-icon-warning" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2L1 21h22L12 2z" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
          <line x1="12" y1="9" x2="12" y2="13" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"/>
          <circle cx="12" cy="17" r="1.3" fill="currentColor"/>
        </svg>
      `,
      riskScoreValue: '92 / 100',
      riskScoreLevel: 'Critical risk',
      riskPercent: 92,
      checksHeading: 'Detected reasons',
      checks: [
        {
          name: 'Suspicious domain characteristics',
          status: 'Flagged',
          type: 'danger',
          icon: `
            <svg class="check-icon check-icon-danger" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
              <line x1="12" y1="8" x2="12" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              <circle cx="12" cy="16" r="1" fill="currentColor"/>
            </svg>
          `,
        },
        {
          name: 'Possible impersonation of a trusted website',
          status: 'Detected',
          type: 'danger',
          icon: `
            <svg class="check-icon check-icon-danger" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
              <line x1="12" y1="8" x2="12" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              <circle cx="12" cy="16" r="1" fill="currentColor"/>
            </svg>
          `,
        },
        {
          name: 'Suspicious URL structure',
          status: 'Flagged',
          type: 'danger',
          icon: `
            <svg class="check-icon check-icon-danger" viewBox="0 0 24 24" aria-hidden="true">
              <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="2"/>
              <line x1="12" y1="8" x2="12" y2="12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
              <circle cx="12" cy="16" r="1" fill="currentColor"/>
            </svg>
          `,
        },
      ],
      recommendation:
        'Do not enter passwords, payment details, or other personal information on this website.',
      bgVideoSrc: './spam_bg.mp4',
      panelBgVideoSrc: './spam_central_bg.mp4',
      showActions: true,
    },
    [STATES.SAFE]: {
      pageTitle: 'PhishGuard – Safe Site',
      url: 'https://www.example.com',
      headerSubtitle: 'URL Security Extension',
      statusClass: 'status-safe',
      statusTitle: 'This website looks safe',
      statusDetail: 'No suspicious URL patterns detected.',
      statusIcon: `
        <svg class="status-icon status-icon-safe" viewBox="0 0 24 24" aria-hidden="true">
          <path d="M12 2L4 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-8-4z" fill="none" stroke="currentColor" stroke-width="2"/>
          <path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      `,
      riskScoreValue: '08 / 100',
      riskScoreLevel: 'Low risk',
      riskPercent: 8,
      checksHeading: 'Security checks',
      checks: [
        {
          name: 'URL structure',
          status: 'Passed',
          type: 'passed',
          icon: `
            <svg class="check-icon check-icon-passed" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M5 13l4 4L19 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          `,
        },
        {
          name: 'Domain indicators',
          status: 'Passed',
          type: 'passed',
          icon: `
            <svg class="check-icon check-icon-passed" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M5 13l4 4L19 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          `,
        },
        {
          name: 'Suspicious characters',
          status: 'Passed',
          type: 'passed',
          icon: `
            <svg class="check-icon check-icon-passed" viewBox="0 0 24 24" aria-hidden="true">
              <path d="M5 13l4 4L19 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          `,
        },
      ],
      recommendation:
        'No obvious warning signs were detected. Continue browsing with normal caution.',
      bgVideoSrc: './Citron.mp4',
      panelBgVideoSrc: './blend.mp4',
      showActions: false,
    },
  };

  let currentState = STATES.PHISHING;

  // DOM Elements cache
  const elements = {};

  function initElements() {
    elements.body = document.body;
    elements.panel = document.querySelector('.extension-panel');
    elements.bgVideo = document.getElementById('bgVideo');
    elements.panelBgVideo = document.getElementById('panelBgVideo');
    elements.headerSubtitle = document.getElementById('headerSubtitle');
    elements.urlField = document.getElementById('currentUrlField');
    elements.statusSection = document.getElementById('statusSection');
    elements.statusIconWrapper = document.getElementById('statusIconWrapper');
    elements.statusTitle = document.getElementById('statusTitle');
    elements.statusDetail = document.getElementById('statusDetail');
    elements.riskScoreValue = document.getElementById('riskScoreValue');
    elements.riskLevel = document.getElementById('riskLevel');
    elements.riskFill = document.getElementById('riskFill');
    elements.checksHeading = document.getElementById('checksHeading');
    elements.checksList = document.getElementById('checksList');
    elements.recBody = document.getElementById('recBody');
    elements.actionSection = document.getElementById('actionSection');
    elements.panelBody = document.getElementById('panelBody');
    elements.confirmationView = document.getElementById('confirmationView');
    elements.btnBackToSafety = document.getElementById('btnBackToSafety');
    elements.btnDismissAnyway = document.getElementById('btnDismissAnyway');
    elements.btnStatePhishing = document.getElementById('btnStatePhishing');
    elements.btnStateSafe = document.getElementById('btnStateSafe');
    elements.avoidBtn = document.getElementById('avoidBtn');
    elements.closeBtn = document.getElementById('closeBtn');
    elements.settingsIcon = document.getElementById('settingsIcon');
  }

  function playVideo(videoEl) {
    if (!videoEl) return;
    videoEl.muted = true;
    videoEl.defaultMuted = true;
    const playPromise = videoEl.play();
    if (playPromise !== undefined) {
      playPromise.catch(function () {
        // Handled silently
      });
    }
  }

  function switchVideo(videoEl, newSrc) {
    if (!videoEl) return;
    const currentSrc = videoEl.getAttribute('src') || '';
    if (currentSrc !== newSrc) {
      videoEl.setAttribute('src', newSrc);
      const sourceEl = videoEl.querySelector('source');
      if (sourceEl) {
        sourceEl.setAttribute('src', newSrc);
      }
      videoEl.load();
      playVideo(videoEl);
    } else {
      playVideo(videoEl);
    }
  }

  function setState(state) {
    if (!STATE_DATA[state]) return;
    currentState = state;
    const data = STATE_DATA[state];
    hideConfirmation();

    // 1. Update document title
    document.title = data.pageTitle;

    // 2. Update state classes on body and panel
    if (state === STATES.PHISHING) {
      elements.body.classList.add('state-phishing');
      elements.body.classList.remove('state-safe');
      elements.panel.classList.add('state-phishing');
      elements.panel.classList.remove('state-safe');
      if (elements.btnStatePhishing) elements.btnStatePhishing.classList.add('active');
      if (elements.btnStateSafe) elements.btnStateSafe.classList.remove('active');
    } else {
      elements.body.classList.add('state-safe');
      elements.body.classList.remove('state-phishing');
      elements.panel.classList.add('state-safe');
      elements.panel.classList.remove('state-phishing');
      if (elements.btnStateSafe) elements.btnStateSafe.classList.add('active');
      if (elements.btnStatePhishing) elements.btnStatePhishing.classList.remove('active');
    }

    // 3. Update background videos
    switchVideo(elements.bgVideo, data.bgVideoSrc);
    switchVideo(elements.panelBgVideo, data.panelBgVideoSrc);

    // 4. Update Header Subtitle
    if (elements.headerSubtitle) {
      elements.headerSubtitle.textContent = data.headerSubtitle;
    }

    // 5. Update URL display
    if (elements.urlField) {
      elements.urlField.textContent = data.url;
      elements.urlField.setAttribute('title', data.url);
    }

    // 6. Update Status block
    if (elements.statusSection) {
      elements.statusSection.className = `status-card ${data.statusClass}`;
    }
    if (elements.statusIconWrapper) {
      elements.statusIconWrapper.innerHTML = data.statusIcon;
    }
    if (elements.statusTitle) {
      elements.statusTitle.textContent = data.statusTitle;
    }
    if (elements.statusDetail) {
      elements.statusDetail.textContent = data.statusDetail;
    }

    // 7. Update Risk score
    if (elements.riskScoreValue) {
      elements.riskScoreValue.textContent = data.riskScoreValue;
    }
    if (elements.riskLevel) {
      elements.riskLevel.textContent = data.riskScoreLevel;
    }
    if (elements.riskFill) {
      elements.riskFill.style.width = data.riskPercent + '%';
    }

    // 8. Update Checks/Reasons
    if (elements.checksHeading) {
      elements.checksHeading.textContent = data.checksHeading;
    }
    if (elements.checksList) {
      elements.checksList.innerHTML = data.checks
        .map(
          (item) => `
          <li class="check-item check-item-${item.type}">
            <div class="check-left">
              ${item.icon}
              <span class="check-name">${item.name}</span>
            </div>
            <span class="check-status status-badge-${item.type}">${item.status}</span>
          </li>
        `
        )
        .join('');
    }

    // 9. Update Recommendation
    if (elements.recBody) {
      elements.recBody.textContent = data.recommendation;
    }

    // 10. Update Actions section
    if (elements.actionSection) {
      elements.actionSection.style.display = data.showActions ? 'flex' : 'none';
    }
  }

  function showConfirmation() {
    if (!elements.confirmationView || !elements.panelBody) return;
    elements.panelBody.style.display = 'none';
    elements.confirmationView.style.display = 'flex';
    elements.confirmationView.setAttribute('aria-hidden', 'false');
    if (elements.headerSubtitle) {
      elements.headerSubtitle.textContent = '⚠️ Confirm: Dismiss Security Warning';
    }
  }

  function hideConfirmation() {
    if (!elements.confirmationView || !elements.panelBody) return;
    elements.confirmationView.style.display = 'none';
    elements.confirmationView.setAttribute('aria-hidden', 'true');
    elements.panelBody.style.display = 'flex';
    if (elements.headerSubtitle && STATE_DATA[currentState]) {
      elements.headerSubtitle.textContent = STATE_DATA[currentState].headerSubtitle;
    }
  }

  function handleDismissAnyway() {
    const alertBox = document.createElement('div');
    alertBox.className = 'safety-alert-banner';
    alertBox.innerHTML = `
      <div class="alert-content">
        <strong>Warning Dismissed</strong>
        <span>You have chosen to dismiss this warning. The website remains unverified and high risk.</span>
        <button type="button" class="confirm-btn back-safety-btn" id="btnRecheck" style="margin-top: 8px; align-self: center;">
          Re-enable Protection
        </button>
      </div>
    `;
    elements.panel.appendChild(alertBox);
    const recheckBtn = alertBox.querySelector('#btnRecheck');
    if (recheckBtn) {
      recheckBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        alertBox.remove();
        hideConfirmation();
      });
    }
  }

  function setupEventListeners() {
    // State switcher buttons
    if (elements.btnStatePhishing) {
      elements.btnStatePhishing.addEventListener('click', function () {
        setState(STATES.PHISHING);
      });
    }
    if (elements.btnStateSafe) {
      elements.btnStateSafe.addEventListener('click', function () {
        setState(STATES.SAFE);
      });
    }

    // Clicking settings toggles state for quick testing
    if (elements.settingsIcon) {
      elements.settingsIcon.addEventListener('click', function () {
        const nextState = currentState === STATES.PHISHING ? STATES.SAFE : STATES.PHISHING;
        setState(nextState);
      });
    }

    // Avoid This Website button action
    if (elements.avoidBtn) {
      elements.avoidBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        const alertBox = document.createElement('div');
        alertBox.className = 'safety-alert-banner';
        alertBox.innerHTML = `
          <div class="alert-content">
            <strong>Navigating away to safety...</strong>
            <span>Closing unsafe page. Stay protected with PhishGuard.</span>
          </div>
        `;
        elements.panel.appendChild(alertBox);
        setTimeout(function () {
          if (window.history.length > 1) {
            window.history.back();
          } else {
            alertBox.remove();
          }
        }, 1200);
      });
    }

    // Dismiss button on phishing warning interface: opens confirmation interface
    if (elements.closeBtn) {
      elements.closeBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        showConfirmation();
      });
    }

    // Confirmation interface: "Go Back to Safety" returns to phishing warning
    if (elements.btnBackToSafety) {
      elements.btnBackToSafety.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        hideConfirmation();
      });
    }

    // Confirmation interface: "Dismiss Anyway" confirms choice without marking safe
    if (elements.btnDismissAnyway) {
      elements.btnDismissAnyway.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        handleDismissAnyway();
      });
    }
  }

  // Check URL query parameters for initial state e.g. ?state=safe
  function getInitialState() {
    const params = new URLSearchParams(window.location.search);
    const paramState = params.get('state');
    if (paramState === 'safe') return STATES.SAFE;
    if (paramState === 'phishing') return STATES.PHISHING;
    return STATES.PHISHING; // Default to requested phishing state
  }

  // Initialize on DOM load
  document.addEventListener('DOMContentLoaded', function () {
    initElements();
    setupEventListeners();
    const initialState = getInitialState();
    setState(initialState);
    playVideo(elements.bgVideo);
    playVideo(elements.panelBgVideo);
  });

  // Expose global API for external integration (e.g. extension background detector)
  window.PhishGuard = {
    setState: setState,
    getState: function () {
      return currentState;
    },
    STATES: STATES,
  };
})();
