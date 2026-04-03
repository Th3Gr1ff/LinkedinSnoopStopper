// LinkedIn Shield - Content Script
// Runs at document_start to neutralize extension scanning before LinkedIn's code executes

(function() {
  'use strict';

  // ─── 1. Neutralize Chrome/extension enumeration APIs ───────────────────────
  // LinkedIn scans for extensions by probing chrome.runtime and injecting
  // resource URLs to detect if extensions are installed.

  if (typeof window.chrome !== 'undefined') {
    try {
      // Block extension resource URL probing
      const originalFetch = window.fetch;
      window.fetch = function(resource, init) {
        const url = (typeof resource === 'string') ? resource : resource?.url || '';
        // Block attempts to fetch chrome-extension:// URLs (extension detection)
        if (url.startsWith('chrome-extension://') || url.startsWith('moz-extension://')) {
          console.debug('[LinkedIn Shield] Blocked extension probe:', url);
          return Promise.reject(new TypeError('Network request failed'));
        }
        return originalFetch.apply(this, arguments);
      };
    } catch(e) {}
  }

  // ─── 2. Block XMLHttpRequest to known tracking endpoints ───────────────────
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  const BLOCKED_XHR_PATTERNS = [
    /humanab\.com/i,
    /px-cdn\.net/i,
    /perimeterx/i,
    /humansecurity\.com/i,
    /google-analytics\.com/i,
    /googletagmanager\.com/i,
    /doubleclick\.net/i,
    /demdex\.net/i,
    /adsymptotic\.com/i,
    /snap\.licdn\.com/i,
    /px\.ads\.linkedin\.com/i,
    /\/li\/track/i,
    /[?&](trk|trackingId|fingerprint)=/i
  ];

  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    const urlStr = String(url);
    const shouldBlock = BLOCKED_XHR_PATTERNS.some(p => p.test(urlStr));
    if (shouldBlock) {
      console.debug('[LinkedIn Shield] Blocked XHR:', urlStr);
      this._blocked = true;
      return;
    }
    this._url = urlStr;
    return originalXHROpen.apply(this, [method, url, ...rest]);
  };

  XMLHttpRequest.prototype.send = function(...args) {
    if (this._blocked) return;
    return originalXHRSend.apply(this, args);
  };

  // ─── 3. Neutralize navigator fingerprinting ────────────────────────────────
  // LinkedIn's fingerprinting script reads navigator properties to build a
  // device fingerprint. We spoof the noisiest ones.

  try {
    // Spoof plugin list (used heavily for fingerprinting)
    Object.defineProperty(navigator, 'plugins', {
      get: () => [],
      configurable: true
    });

    // Spoof mimeTypes
    Object.defineProperty(navigator, 'mimeTypes', {
      get: () => [],
      configurable: true
    });

    // Harden against battery API fingerprinting
    if (navigator.getBattery) {
      navigator.getBattery = () => Promise.reject(new Error('Not available'));
    }
  } catch(e) {}

  // ─── 4. Block canvas fingerprinting ────────────────────────────────────────
  // Add subtle noise to canvas output so the fingerprint changes each session

  try {
    const originalGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function(type, ...args) {
      const ctx = originalGetContext.apply(this, [type, ...args]);
      if (!ctx) return ctx;

      if (type === '2d') {
        const originalGetImageData = ctx.getImageData.bind(ctx);
        ctx.getImageData = function(x, y, w, h) {
          const imageData = originalGetImageData(x, y, w, h);
          // Add 1-bit noise to make fingerprint unique per session
          for (let i = 0; i < imageData.data.length; i += 100) {
            imageData.data[i] ^= 1;
          }
          return imageData;
        };
      }
      return ctx;
    };
  } catch(e) {}

  // ─── 5. Block AudioContext fingerprinting ──────────────────────────────────
  try {
    const OrigAudioContext = window.AudioContext || window.webkitAudioContext;
    if (OrigAudioContext) {
      const OrigAnalyser = OrigAudioContext.prototype.createAnalyser;
      OrigAudioContext.prototype.createAnalyser = function() {
        const analyser = OrigAnalyser.apply(this, arguments);
        const originalGetFloatFrequency = analyser.getFloatFrequencyData.bind(analyser);
        analyser.getFloatFrequencyData = function(array) {
          originalGetFloatFrequency(array);
          // Add noise
          for (let i = 0; i < array.length; i += 10) {
            array[i] += (Math.random() - 0.5) * 0.0001;
          }
        };
        return analyser;
      };
    }
  } catch(e) {}

  // ─── 6. Remove tracking parameters from links ──────────────────────────────
  const TRACKING_PARAMS = [
    'trk', 'trkEmail', 'trkInfo', 'trackingId', 'lipi', 'licu'
  ];

  function cleanTrackingParams(url) {
    try {
      const u = new URL(url);
      let changed = false;
      TRACKING_PARAMS.forEach(p => {
        if (u.searchParams.has(p)) {
          u.searchParams.delete(p);
          changed = true;
        }
      });
      return changed ? u.toString() : url;
    } catch(e) {
      return url;
    }
  }

  // Clean links on click before navigation
  document.addEventListener('click', function(e) {
    const link = e.target.closest('a[href]');
    if (!link) return;
    const cleaned = cleanTrackingParams(link.href);
    if (cleaned !== link.href) {
      e.preventDefault();
      window.location.href = cleaned;
    }
  }, true);

  console.info('[LinkedIn Shield] Active — fingerprinting and tracking protections enabled.');
})();
