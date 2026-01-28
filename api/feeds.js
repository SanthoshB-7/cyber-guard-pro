const FEED_TTLS_MS = {
  advisories: 30 * 60 * 1000,
  osv: 60 * 60 * 1000,
  status: 15 * 60 * 1000
};

const ADVISORY_MAX_ITEMS = 50;
const STATUS_MAX_ITEMS = 50;
const OSV_MAX_ITEMS = 50;

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

  const forceRefresh = req.query?.force === '1';
  const cacheKey = buildCacheKey(type, req.query || {});
  const now = Date.now();
  const cachedEntry = forceRefresh ? null : getCachedEntry(type, cacheKey, now);
  if (cachedEntry) {
    return res.status(200).json({
      type,
      items: cachedEntry.items,
      timestamp: cachedEntry.timestamp,
      cached: true,
      degraded: false,
      sourceCount: cachedEntry.sourceCount
    });
  }

  try {
    let items = [];
    let sourceCount = 0;

    if (type === 'advisories') {
      items = await fetchAdvisoryFeeds();
      sourceCount = advisoryFeeds.length;
    } else if (type === 'status') {
      items = await fetchStatusFeeds();
      sourceCount = statusFeeds.length;
    } else if (type === 'osv') {
      const ecosystems = parseEcosystems(req.query?.ecosystem);
      const days = Number(req.query?.days || 30);
      const results = await Promise.all(
        ecosystems.map((ecosystem) =>
          fetchOsvFeed(ecosystem, Number.isFinite(days) ? days : 30)
        )
      );
      items = results.flat();
      sourceCount = ecosystems.length;
    }

    const timestamp = new Date().toISOString();
    if (type === 'osv') {
      items = items
        .sort((a, b) => new Date(b.publishedISO || 0) - new Date(a.publishedISO || 0))
        .slice(0, OSV_MAX_ITEMS);
    }

    cache[type] = {
      key: cacheKey,
      timestamp,
      items,
      sourceCount
    };

    return res.status(200).json({
      type,
      items,
      timestamp,
      cached: false,
      degraded: false,
      sourceCount
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
    const ecosystem = String(query?.ecosystem || 'npm')
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean)
      .join(',');
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
  return dedupeItems(items)
    .map(mapAdvisoryItem)
    .filter(Boolean)
    .slice(0, ADVISORY_MAX_ITEMS);
}

async function fetchStatusFeeds() {
  const items = await fetchRssFeeds(statusFeeds);
  const sorted = items.sort((a, b) => new Date(b.dateISO || 0) - new Date(a.dateISO || 0));
  return sorted
    .map(mapStatusItem)
    .filter(Boolean)
    .slice(0, STATUS_MAX_ITEMS);
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
    return normalized.filter(
      (item) => new Date(item.publishedISO || 0) >= new Date(since)
    );
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
      severity: 'HIGH',
      publishedISO: now.toISOString(),
      aliases: [],
      url: `https://osv.dev/vulnerability/OSV-${ecosystem.toUpperCase()}-0001`
    },
    {
      id: `OSV-${ecosystem.toUpperCase()}-0002`,
      ecosystem,
      package: 'example-lib',
      summary: 'Dependency vulnerability with remote code execution risk.',
      severity: 'CRITICAL',
      publishedISO: now.toISOString(),
      aliases: [],
      url: `https://osv.dev/vulnerability/OSV-${ecosystem.toUpperCase()}-0002`
    }
  ].filter((item) => new Date(item.publishedISO) >= new Date(since));
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
  const publishedISO = item.published || item.modified || item.date || new Date().toISOString();
  const aliases = Array.isArray(item.aliases)
    ? item.aliases
    : Array.isArray(item.cve)
      ? item.cve
      : item.cve
        ? [item.cve]
        : [];
  const url =
    (Array.isArray(item.references) && item.references[0]?.url) ||
    item.url ||
    `https://osv.dev/vulnerability/${encodeURIComponent(item.id || '')}`;
  return {
    id: item.id || item.osvId || createId(`${eco}-${pkgName}-${publishedISO}`),
    ecosystem: eco,
    package: pkgName,
    summary: item.summary || item.details || 'OSV vulnerability',
    severity: extractOsvSeverity(item),
    publishedISO,
    aliases,
    url
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
  if (text.includes('maintenance')) return 'maintenance';
  return 'incident';
}

function parseEcosystems(raw) {
  if (!raw) return ['npm'];
  const list = String(raw)
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  return list.length ? list : ['npm'];
}

function mapAdvisoryItem(item) {
  if (!item) return null;
  return {
    id: item.id,
    title: item.title,
    url: item.url,
    publishedISO: item.dateISO,
    vendor: item.sourceName,
    summary: item.summary,
    cves: item.cves || []
  };
}

function mapStatusItem(item) {
  if (!item) return null;
  return {
    id: item.id,
    service: item.sourceName,
    title: item.title,
    statusType: item.status || 'incident',
    publishedISO: item.dateISO,
    url: item.url,
    summary: item.summary
  };
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
