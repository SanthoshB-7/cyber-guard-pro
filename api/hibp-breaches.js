const hibpCacheTtlMs = 24 * 60 * 60 * 1000;
let hibpCache = null;

export default async function handler(req, res) {
  const timestamp = new Date().toISOString();
  try {
    const breaches = await fetchHibpBreaches();
    const responsePayload = {
      breaches,
      timestamp,
      source: 'hibp',
      mode: 'verified'
    };
    hibpCache = {
      ...responsePayload,
      cachedAt: Date.now()
    };
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(responsePayload);
  } catch (error) {
    res.setHeader('Content-Type', 'application/json');
    if (hibpCache && Date.now() - hibpCache.cachedAt <= hibpCacheTtlMs) {
      res.status(200).json({
        breaches: hibpCache.breaches,
        timestamp,
        source: hibpCache.source,
        mode: hibpCache.mode,
        stale: true
      });
      return;
    }
    res.status(503).json({
      error: error.message,
      timestamp,
      source: 'hibp',
      mode: 'verified'
    });
  }
}

async function fetchHibpBreaches() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);
  let response;
  try {
    response = await fetch('https://haveibeenpwned.com/api/v3/breaches', {
      headers: {
        accept: 'application/json',
        'user-agent': 'CyberSecCommand (contact: https://github.com/)'
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new Error('HIBP API error');
  }

  const data = await response.json();
  if (!Array.isArray(data)) {
    throw new Error('HIBP response invalid');
  }

  return data.map(entry => normalizeHibpBreach(entry)).sort((a, b) => {
    const timeA = Date.parse(a.date) || 0;
    const timeB = Date.parse(b.date) || 0;
    return timeB - timeA;
  }).slice(0, 50);
}

function normalizeHibpBreach(entry) {
  const pwnCount = Number(entry.PwnCount || 0);
  const dataClasses = Array.isArray(entry.DataClasses) ? entry.DataClasses.join(', ') : 'Not disclosed';
  const description = stripHtml(entry.Description || '');
  return {
    name: entry.Name || entry.Title || 'Unknown',
    date: entry.BreachDate || entry.AddedDate || new Date().toISOString().split('T')[0],
    recordsAffected: pwnCount || 0,
    dataExposed: dataClasses,
    description: description || 'Reported data breach',
    url: entry.BreachURL || (entry.Domain ? `https://${entry.Domain}` : `https://haveibeenpwned.com/PwnedWebsites#${encodeURIComponent(entry.Name || '')}`),
    severity: severityFromPwnCount(pwnCount),
    category: 'breach',
    sourceName: 'HIBP'
  };
}

function severityFromPwnCount(count) {
  if (count >= 50000000) return 'CRITICAL';
  if (count >= 5000000) return 'HIGH';
  if (count >= 500000) return 'MEDIUM';
  return 'LOW';
}

function stripHtml(value) {
  return String(value || '').replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}
