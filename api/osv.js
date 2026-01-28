const CACHE_TTL_MS = 60 * 60 * 1000;
const CACHE_HEADER = 's-maxage=3600, stale-while-revalidate=600';
const FORCE_REFRESH_MIN_MS = 10 * 60 * 1000;
const MAX_ITEMS = 50;
const LIST_LIMIT = 120;

const DEFAULT_ECOSYSTEMS = ['npm', 'PyPI', 'Maven'];

let cache = {
  data: null,
  fetchedAt: 0
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', CACHE_HEADER);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const now = Date.now();
  const force = req.query?.force === '1';
  const canForceRefresh = now - cache.fetchedAt > FORCE_REFRESH_MIN_MS;
  const shouldServeCache = cache.data && (!force || !canForceRefresh) && now - cache.fetchedAt < CACHE_TTL_MS;

  if (shouldServeCache) {
    return res.status(200).json({
      ...cache.data,
      cached: true,
      degraded: false
    });
  }

  const ecosystems = parseEcosystems(req.query?.ecosystem);
  const days = Math.max(1, Number(req.query?.days) || 7);
  const minDate = Date.now() - days * 24 * 60 * 60 * 1000;

  try {
    const ecosystemResults = await Promise.all(
      ecosystems.map(async (ecosystem) => {
        const listUrl = `https://api.osv.dev/v1/list?ecosystem=${encodeURIComponent(ecosystem)}`;
        const listData = await fetchJson(listUrl);
        const ids = normalizeIds(listData).slice(0, LIST_LIMIT);
        const detailItems = await fetchDetails(ids);
        return detailItems.map(item => normalizeItem(item, ecosystem));
      })
    );

    const items = ecosystemResults
      .flat()
      .filter(Boolean)
      .filter(item => new Date(item.publishedISO).getTime() >= minDate)
      .sort((a, b) => new Date(b.publishedISO) - new Date(a.publishedISO))
      .slice(0, MAX_ITEMS);

    const payload = {
      items,
      timestamp: new Date().toISOString(),
      sourceCount: ecosystems.length
    };

    cache = {
      data: payload,
      fetchedAt: now
    };

    return res.status(200).json({
      ...payload,
      cached: false,
      degraded: false
    });
  } catch (error) {
    if (cache.data) {
      return res.status(200).json({
        ...cache.data,
        cached: true,
        degraded: true
      });
    }
    return res.status(500).json({ error: 'OSV API failed', details: error.message });
  }
}

function parseEcosystems(raw) {
  if (!raw) return DEFAULT_ECOSYSTEMS;
  const list = String(raw)
    .split(',')
    .map(value => value.trim())
    .filter(Boolean);
  return list.length ? list : DEFAULT_ECOSYSTEMS;
}

async function fetchJson(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'CyberSecCommand/1.0'
      }
    });
    if (!response.ok) {
      throw new Error(`OSV request failed (${response.status})`);
    }
    return await response.json();
  } finally {
    clearTimeout(timeout);
  }
}

function normalizeIds(listData) {
  if (!listData) return [];
  if (Array.isArray(listData.vulns)) {
    return listData.vulns.map(entry => (typeof entry === 'string' ? entry : entry.id)).filter(Boolean);
  }
  if (Array.isArray(listData.ids)) {
    return listData.ids.map(entry => (typeof entry === 'string' ? entry : entry.id)).filter(Boolean);
  }
  return [];
}

async function fetchDetails(ids) {
  const results = [];
  const batchSize = 10;
  for (let i = 0; i < ids.length; i += batchSize) {
    const batch = ids.slice(i, i + batchSize);
    const batchResults = await Promise.all(batch.map(async (id) => {
      try {
        return await fetchJson(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`);
      } catch (error) {
        return null;
      }
    }));
    results.push(...batchResults.filter(Boolean));
    if (results.length >= MAX_ITEMS) break;
  }
  return results;
}

function normalizeItem(vuln, fallbackEcosystem) {
  if (!vuln || !vuln.id) return null;
  const affected = Array.isArray(vuln.affected) ? vuln.affected : [];
  const pkg = affected[0]?.package || {};
  const ecosystem = pkg.ecosystem || fallbackEcosystem || 'Unknown';
  const name = pkg.name || 'Unknown package';
  const publishedISO = vuln.published || vuln.modified || new Date().toISOString();
  const aliases = Array.isArray(vuln.aliases) ? vuln.aliases : [];
  const severity = extractSeverity(vuln);
  const url = extractUrl(vuln) || `https://osv.dev/vulnerability/${encodeURIComponent(vuln.id)}`;

  return {
    id: vuln.id,
    ecosystem,
    package: name,
    summary: vuln.summary || vuln.details || 'No summary provided',
    severity,
    publishedISO,
    aliases,
    url
  };
}

function extractSeverity(vuln) {
  const dbSeverity = vuln.database_specific?.severity;
  if (dbSeverity) return normalizeSeverityLabel(dbSeverity);
  const entries = Array.isArray(vuln.severity) ? vuln.severity : [];
  for (const entry of entries) {
    if (entry.score) {
      const value = parseFloat(String(entry.score).match(/\d+(?:\.\d+)?/)?.[0]);
      if (!Number.isNaN(value)) return scoreToSeverity(value);
    }
  }
  const cvss = vuln.database_specific?.cvss;
  if (typeof cvss === 'number') return scoreToSeverity(cvss);
  return 'UNKNOWN';
}

function normalizeSeverityLabel(value) {
  const normalized = String(value).toUpperCase();
  if (normalized.includes('CRITICAL')) return 'CRITICAL';
  if (normalized.includes('HIGH')) return 'HIGH';
  if (normalized.includes('MODERATE') || normalized.includes('MEDIUM')) return 'MEDIUM';
  if (normalized.includes('LOW')) return 'LOW';
  return 'UNKNOWN';
}

function scoreToSeverity(score) {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

function extractUrl(vuln) {
  const refs = Array.isArray(vuln.references) ? vuln.references : [];
  const preferred = refs.find(ref => ref.type === 'ADVISORY') || refs.find(ref => ref.type === 'REPORT') || refs[0];
  return preferred?.url || '';
}
