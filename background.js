// LinkedIn Shield - Background Script
// Blocks fingerprinting, extension scanning, and surveillance trackers

const BLOCKED_DOMAINS = [
  // HUMAN Security / PerimeterX (invisible tracking pixel + fingerprinting)
  "humanab.com",
  "px-cdn.net",
  "px-client.net",
  "pxi.pub",
  "perimeterx.net",
  "perimeterx.com",
  "edgecastcdn.net",
  "humansecurity.com",
  // LinkedIn's own fingerprinting/analytics endpoints
  "snap.licdn.com",
  "px.ads.linkedin.com",
  "analytics.pointdrive.linkedin.com",
  // Google tracking loaded by LinkedIn
  "google-analytics.com",
  "googletagmanager.com",
  "googletagservices.com",
  "doubleclick.net",
  // Other known ad/tracking networks loaded by LinkedIn
  "adsymptotic.com",
  "serving-sys.com",
  "criteo.com",
  "bluekai.com",
  "demdex.net",
  "exelate.com",
  "rlcdn.com",
  "quantserve.com",
  "scorecardresearch.com"
];

// LinkedIn's internal extension-scanning and fingerprinting URL patterns
const BLOCKED_URL_PATTERNS = [
  // Extension scanning endpoints (checks for installed browser extensions)
  /linkedin\.com.*\/extension.scan/i,
  /linkedin\.com.*\/browser.info/i,
  /linkedin\.com.*\/plugin.detect/i,
  // Voyager API calls that include fingerprint/device data
  /linkedin\.com\/voyager\/api\/identity\/dash\/profile.*fingerprint/i,
  // Known tracking beacon paths
  /linkedin\.com\/li\/track/i,
  /linkedin\.com\/px\//i,
  /licdn\.com\/px\//i,
  // Zero-pixel tracking images
  /1x1\.gif/i,
  /pixel\.gif/i,
  /tracking\.gif/i
];

// Stats tracking
let stats = {
  blocked: 0,
  allowed: 0,
  sessionStart: Date.now()
};

// Load persisted stats
browser.storage.local.get("stats").then(data => {
  if (data.stats) {
    stats.blocked = data.stats.blocked || 0;
  }
});

function shouldBlock(url, type) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.replace(/^www\./, "");

    // Check blocked domains
    for (const domain of BLOCKED_DOMAINS) {
      if (hostname === domain || hostname.endsWith("." + domain)) {
        return { block: true, reason: `Blocked domain: ${domain}` };
      }
    }

    // Check URL patterns
    for (const pattern of BLOCKED_URL_PATTERNS) {
      if (pattern.test(url)) {
        return { block: true, reason: `Blocked pattern: ${pattern.source}` };
      }
    }

    // Block invisible/zero-pixel tracking images from licdn.com
    if (type === "image" && (hostname.endsWith("licdn.com") || hostname.endsWith("linkedin.com"))) {
      // Allow real content images, block tiny trackers
      if (/[?&](trk|tracking|beacon|pixel|event)=/i.test(url)) {
        return { block: true, reason: "Tracking pixel parameter" };
      }
    }

    return { block: false };
  } catch (e) {
    return { block: false };
  }
}

// Main request interceptor
browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    // Only act on LinkedIn pages
    if (!details.originUrl && !details.documentUrl) return {};

    const originUrl = details.originUrl || details.documentUrl || "";
    const isLinkedInPage = /linkedin\.com/.test(originUrl);

    if (!isLinkedInPage) return {};

    const result = shouldBlock(details.url, details.type);

    if (result.block) {
      stats.blocked++;
      browser.storage.local.set({ stats });
      console.log(`[LinkedIn Shield] BLOCKED: ${details.url} — ${result.reason}`);
      return { cancel: true };
    }

    stats.allowed++;
    return {};
  },
  {
    urls: ["<all_urls>"],
    types: [
      "script", "xmlhttprequest", "image", "sub_frame",
      "stylesheet", "object", "ping", "beacon", "media"
    ]
  },
  ["blocking"]
);

// Block response headers that leak info or enable HSTS tracking
browser.webRequest.onHeadersReceived.addListener(
  function(details) {
    const originUrl = details.originUrl || details.documentUrl || "";
    if (!/linkedin\.com/.test(originUrl)) return {};

    let headers = details.responseHeaders || [];

    // Remove headers used for device/browser fingerprinting correlation
    const removeHeaders = [
      "x-li-fabric",
      "x-li-pop",
      "x-li-proto",
      "x-li-uuid",
      "x-content-type-options", // keep for security but log
    ];

    headers = headers.filter(h =>
      !removeHeaders.includes(h.name.toLowerCase())
    );

    return { responseHeaders: headers };
  },
  {
    urls: ["*://*.linkedin.com/*", "*://*.licdn.com/*"]
  },
  ["blocking", "responseHeaders"]
);

// Message handler for popup
browser.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "getStats") {
    sendResponse({
      blocked: stats.blocked,
      allowed: stats.allowed,
      sessionStart: stats.sessionStart
    });
  }
  if (message.type === "resetStats") {
    stats.blocked = 0;
    stats.allowed = 0;
    stats.sessionStart = Date.now();
    browser.storage.local.set({ stats });
    sendResponse({ ok: true });
  }
});
