// LinkedIn Shield - Popup Script

function formatUptime(ms) {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0) return `${h}h ${m % 60}m`;
  if (m > 0) return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function updateUI(stats) {
  document.getElementById('blockedCount').textContent = stats.blocked.toLocaleString();
  const uptime = Date.now() - stats.sessionStart;
  const uptimeStr = formatUptime(uptime);
  document.getElementById('sessionTime').textContent = uptimeStr;
  document.getElementById('uptimeLabel').textContent = uptimeStr;
}

// Fetch stats from background
browser.runtime.sendMessage({ type: 'getStats' }).then(stats => {
  updateUI(stats);
});

// Reset button
document.getElementById('resetBtn').addEventListener('click', () => {
  browser.runtime.sendMessage({ type: 'resetStats' }).then(() => {
    document.getElementById('blockedCount').textContent = '0';
    document.getElementById('sessionTime').textContent = '0s';
    document.getElementById('uptimeLabel').textContent = '0s';
  });
});

// Refresh every second while popup is open
setInterval(() => {
  browser.runtime.sendMessage({ type: 'getStats' }).then(updateUI);
}, 1000);
