// Apply the saved theme before first paint.
try { const t = localStorage.getItem("agent-proxy-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch {}
