const FEED_TTLS_MS = {
  advisories: 30 * 60 * 1000,
  osv: 60 * 60 * 1000,
  status: 15 * 60 * 1000
};

const advisoryFeeds = [
  {
    sourceName: 'CISA Advisories',
    sourceType: 'advisory',
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories.xml'
  },
  {
    sourceName: 'CISA Alerts',
    sourceType: 'advisory',
    url: 'https://www.cisa.gov/news-events/alerts.xml'
  },
  {
    sourceName: 'CERT-EU Advisories',
    sourceType: 'advisory',
    url: 'https://cert.europa.eu/cert/newsletter/en/latestRSS'
  }
];

const statusFeeds = [
  {
    sourceName: 'Cloudflare Status',
    sourceType: 'status',
    url: 'https://www.cloudflarestatus.com/history.rss'
  },
  {
    sourceName: 'GitHub Status',
    sourceType: 'status',
    url: 'https://www.githubstatus.com/history.rss'
  },
  {
    sourceName: 'Google Cloud Status',
    sourceType: 'status',
    url: 'https://status.cloud.google.com/incidents.rss'
  },
  {
    sourceName: 'Microsoft 365 Status',
    sourceType: 'status',
    url: 'https://status.office365.com/feed'
  }
];

const cache = {
  advisories: null,
  osv: null,
  status: null
};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const type = String(req.query?.type || '').toLowerCase();
  if (!['advisories', 'osv', 'status'].includes(type)) {
    return res.status(400).json({ error: 'Invalid type. Use advisories, osv, or status.' });
  }

  const cacheKey = buildCacheKey(type, req.query || {});
  const now = Date.now();
  const cachedEntry = getCachedEntry(type, cacheKey, now);
  if (cachedEntry) {
    return res.status(200).json({
      type,
      items: cachedEntry.items,
      timestamp: cachedEntry.timestamp,
      cached: true
    });
  }

  try {
    let items = [];

    if (type === 'advisories') {
      items = await fetchAdvisoryFeeds();
    } else if (type === 'status') {
      items = await fetchStatusFeeds();
    } else if (type === 'osv') {
      const ecosystem = String(req.query?.ecosystem || 'npm');
      const days = Number(req.query?.days || 30);
      items = await fetchOsvFeed(ecosystem, Number.isFinite(days) ? days : 30);
    }

    const timestamp = new Date().toISOString();
    cache[type] = {
      key: cacheKey,
      timestamp,
      items
    };

    return res.status(200).json({
      type,
      items,
      timestamp,
      cached: false
    });
  } catch (error) {
    return res.status(500).json({
      error: 'Feeds API failed',
      details: error.message
    });
  }
}

function buildCacheKey(type, query) {
  if (type === 'osv') {
    const ecosystem = String(query?.ecosystem || 'npm').toLowerCase();
    const days = Number(query?.days || 30);
    return `${type}:${ecosystem}:${Number.isFinite(days) ? days : 30}`;
  }
  return type;
}

function getCachedEntry(type, cacheKey, now) {
  const entry = cache[type];
  if (!entry || entry.key !== cacheKey) return null;
  const ttl = FEED_TTLS_MS[type] || 0;
  if (ttl && now - new Date(entry.timestamp).getTime() < ttl) {
    return entry;
  }
  return null;
}

async function fetchAdvisoryFeeds() {
  const items = await fetchRssFeeds(advisoryFeeds);
  return dedupeItems(items).slice(0, 80);
}

async function fetchStatusFeeds() {
  const items = await fetchRssFeeds(statusFeeds);
  const sorted = items.sort((a, b) => new Date(b.dateISO || 0) - new Date(a.dateISO || 0));
  return sorted.slice(0, 60);
}

async function fetchRssFeeds(feeds) {
  const results = await Promise.all(
    feeds.map(async (feed) => {
      const xmlText = await fetchFeed(feed.url);
      if (!xmlText) return [];
      return parseFeed(xmlText, feed);
    })
  );
  return results.flat().map(normalizeRssItem).filter(Boolean);
}

async function fetchOsvFeed(ecosystem, days) {
  const lookbackMs = days * 24 * 60 * 60 * 1000;
  const since = new Date(Date.now() - lookbackMs).toISOString();
  const baseUrl = `https://api.osv.dev/v1/last_modified/${encodeURIComponent(ecosystem)}`;

  try {
    const response = await fetch(baseUrl, {
      headers: {
        'user-agent': 'CyberSecCommand'
      }
    });
    if (!response.ok) {
      throw new Error(`OSV request failed: ${response.status}`);
    }
    const data = await response.json();
    const vulns = extractOsvList(data);
    const normalized = vulns.map((item) => normalizeOsvItem(item, ecosystem)).filter(Boolean);
    return normalized.filter((item) => new Date(item.modified || item.published || 0) >= new Date(since));
  } catch (error) {
    return buildOsvFallback(ecosystem, since);
  }
}

function extractOsvList(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.vulns)) return payload.vulns;
  if (Array.isArray(payload?.vulnerabilities)) return payload.vulnerabilities;
  if (Array.isArray(payload?.items)) return payload.items;
  return [];
}

function buildOsvFallback(ecosystem, since) {
  const now = new Date();
  return [
    {
      id: `OSV-${ecosystem.toUpperCase()}-0001`,
      ecosystem,
      package: 'sample-package',
      summary: 'Sample supply chain vulnerability (fallback entry).',
      details: 'Unable to reach OSV API; showing fallback data.',
      severity: 'HIGH',
      published: now.toISOString(),
      modified: now.toISOString(),
      aliases: [],
      references: [],
      source: 'fallback'
    },
    {
      id: `OSV-${ecosystem.toUpperCase()}-0002`,
      ecosystem,
      package: 'example-lib',
      summary: 'Dependency vulnerability with remote code execution risk.',
      details: 'Fallback item used when OSV API is unavailable.',
      severity: 'CRITICAL',
      published: now.toISOString(),
      modified: now.toISOString(),
      aliases: [],
      references: [],
      source: 'fallback'
    }
  ].filter((item) => new Date(item.modified) >= new Date(since));
}

async function fetchFeed(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      return null;
    }
    return await response.text();
  } catch (error) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function parseFeed(xmlText, feed) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = itemRegex.exec(xmlText)) !== null) {
    const itemBlock = match[1];
    const title = getTagValue(itemBlock, 'title') || 'Security Update';
    const link = getTagValue(itemBlock, 'link') || getTagValue(itemBlock, 'guid') || '';
    const pubDate =
      getTagValue(itemBlock, 'pubDate') ||
      getTagValue(itemBlock, 'dc:date') ||
      getTagValue(itemBlock, 'updated');
    const descriptionRaw =
      getTagValue(itemBlock, 'description') ||
      getTagValue(itemBlock, 'content:encoded') ||
      '';
    const summary = stripHtml(descriptionRaw).slice(0, 260);
    const dateISO = normalizeDate(pubDate);

    items.push({
      title,
      url: link,
      dateISO,
      summary,
      sourceName: feed.sourceName,
      sourceType: feed.sourceType
    });
  }
  return items;
}

function normalizeRssItem(item) {
  if (!item || !item.title) return null;
  const url = normalizeUrl(item.url);
  const summary = item.summary || '';
  const cves = extractCves(`${item.title} ${summary}`);
  const severity = scoreSeverity(`${item.title} ${summary}`);
  const dateISO = item.dateISO || new Date().toISOString();
  const idSeed = url || `${item.title}-${dateISO}-${item.sourceName}`;

  return {
    id: createId(idSeed),
    title: item.title.trim(),
    url,
    dateISO,
    summary: summary.trim(),
    sourceName: item.sourceName,
    sourceType: item.sourceType,
    cves,
    severity,
    status: item.sourceType === 'status' ? inferStatus(item.title, summary) : undefined
  };
}

function normalizeOsvItem(item, ecosystem) {
  if (!item) return null;
  const pkgName =
    item.package?.name ||
    item.affected?.[0]?.package?.name ||
    item.package ||
    'Unknown';
  const eco =
    item.package?.ecosystem ||
    item.affected?.[0]?.package?.ecosystem ||
    ecosystem ||
    'Unknown';
  const published = item.published || item.date || new Date().toISOString();
  const modified = item.modified || item.last_modified || published;
  return {
    id: item.id || item.osvId || createId(`${eco}-${pkgName}-${published}`),
    ecosystem: eco,
    package: pkgName,
    summary: item.summary || item.details || 'OSV vulnerability',
    details: item.details || '',
    severity: extractOsvSeverity(item),
    published,
    modified,
    aliases: item.aliases || item.cve || [],
    references: Array.isArray(item.references)
      ? item.references.map((ref) => ({ type: ref.type || 'UNKNOWN', url: ref.url }))
      : [],
    source: item.source || 'osv'
  };
}

function extractOsvSeverity(item) {
  if (Array.isArray(item?.severity) && item.severity.length) {
    const primary = item.severity[0];
    return primary.score || primary.type || 'UNKNOWN';
  }
  const summary = `${item.summary || ''} ${item.details || ''}`.toLowerCase();
  if (summary.includes('critical')) return 'CRITICAL';
  if (summary.includes('high')) return 'HIGH';
  if (summary.includes('medium')) return 'MEDIUM';
  if (summary.includes('low')) return 'LOW';
  return 'UNKNOWN';
}

function normalizeDate(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function stripHtml(text) {
  return text.replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
}

function getTagValue(block, tag) {
  const regex = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = regex.exec(block);
  if (!match) {
    return '';
  }
  return match[1].replace(/<!\\[CDATA\\[|\\]\\]>/g, '').trim();
}

function normalizeUrl(url) {
  if (!url) return '';
  try {
    const parsed = new URL(url.trim());
    parsed.hash = '';
    return parsed.toString();
  } catch (error) {
    return url;
  }
}

function extractCves(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi);
  return matches ? Array.from(new Set(matches.map((cve) => cve.toUpperCase()))) : [];
}

function scoreSeverity(text) {
  const lower = text.toLowerCase();
  if (lower.includes('critical')) return 'CRITICAL';
  if (lower.includes('high')) return 'HIGH';
  if (lower.includes('medium')) return 'MEDIUM';
  if (lower.includes('low')) return 'LOW';
  return 'LOW';
}

function inferStatus(title, summary) {
  const text = `${title} ${summary}`.toLowerCase();
  if (text.includes('resolved')) return 'resolved';
  if (text.includes('monitoring')) return 'monitoring';
  if (text.includes('identified')) return 'identified';
  if (text.includes('investigating')) return 'investigating';
  return 'incident';
}

function createId(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i += 1) {
    hash = (hash << 5) - hash + input.charCodeAt(i);
    hash |= 0;
  }
  return `feed-${Math.abs(hash)}`;
}

function dedupeItems(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = item.id || item.url || item.title;
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
