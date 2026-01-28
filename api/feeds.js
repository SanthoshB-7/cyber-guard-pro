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
  const cveOnly = req.query?.cveOnly === '1' || req.query?.cveOnly === 'true';
  const cacheKey = buildCacheKey(type, req.query || {});
  const now = Date.now();
  const cachedEntry = forceRefresh ? null : getCachedEntry(type, cacheKey, now);
  if (cachedEntry) {
    return res.status(200).json(
      buildResponse({
        type,
        items: cachedEntry.items,
        timestamp: cachedEntry.timestamp,
        cached: true,
        sourceCount: cachedEntry.sourceCount,
        fetchedCount: cachedEntry.fetchedCount,
        parsedCount: cachedEntry.parsedCount,
        filteredCount: cachedEntry.filteredCount,
        errors: cachedEntry.errors,
        filteredByCveOnly: cachedEntry.filteredByCveOnly
      })
    );
  }

  try {
    let items = [];
    let sourceCount = 0;
    let fetchedCount = 0;
    let parsedCount = 0;
    let filteredCount = 0;
    let errors = [];
    let filteredByCveOnly = false;

    if (type === 'advisories') {
      const result = await fetchAdvisoryFeeds({ cveOnly });
      items = result.items;
      fetchedCount = result.fetchedCount;
      parsedCount = result.parsedCount;
      filteredCount = result.filteredCount;
      errors = result.errors;
      filteredByCveOnly = result.filteredByCveOnly;
      sourceCount = advisoryFeeds.length;
    } else if (type === 'status') {
      const result = await fetchStatusFeeds();
      items = result.items;
      fetchedCount = result.fetchedCount;
      parsedCount = result.parsedCount;
      filteredCount = result.filteredCount;
      errors = result.errors;
      sourceCount = statusFeeds.length;
    } else if (type === 'osv') {
      const ecosystems = parseEcosystems(req.query?.ecosystem);
      const days = Number(req.query?.days || 30);
      const results = await Promise.all(
        ecosystems.map((ecosystem) =>
          fetchOsvFeed(ecosystem, Number.isFinite(days) ? days : 30)
        )
      );
      items = results.flatMap((result) => result.items);
      fetchedCount = results.reduce((total, result) => total + result.fetchedCount, 0);
      parsedCount = results.reduce((total, result) => total + result.parsedCount, 0);
      filteredCount = results.reduce((total, result) => total + result.filteredCount, 0);
      errors = results.flatMap((result) => result.errors);
      sourceCount = ecosystems.length;
    }

    const timestamp = new Date().toISOString();
    if (type === 'osv') {
      items = items
        .sort((a, b) => new Date(b.publishedISO || 0) - new Date(a.publishedISO || 0))
        .slice(0, OSV_MAX_ITEMS);
      filteredCount = items.length;
    }

    cache[type] = {
      key: cacheKey,
      timestamp,
      items,
      sourceCount,
      fetchedCount,
      parsedCount,
      filteredCount,
      errors,
      filteredByCveOnly
    };

    return res.status(200).json(
      buildResponse({
        type,
        items,
        timestamp,
        cached: false,
        sourceCount,
        fetchedCount,
        parsedCount,
        filteredCount: type === 'osv' ? items.length : filteredCount,
        errors,
        filteredByCveOnly
      })
    );
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
  if (type === 'advisories') {
    const cveOnly = query?.cveOnly === '1' || query?.cveOnly === 'true';
    return `${type}:${cveOnly ? 'cve-only' : 'all'}`;
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

async function fetchAdvisoryFeeds({ cveOnly = false } = {}) {
  const { items, parsedCount, fetchedCount, errors } = await fetchRssFeeds(advisoryFeeds);
  const mapped = dedupeItems(items).map(mapAdvisoryItem).filter(Boolean);
  const filtered = cveOnly ? mapped.filter((item) => item.cves && item.cves.length > 0) : mapped;
  const filteredByCveOnly = cveOnly && parsedCount > 0 && filtered.length === 0;
  return {
    items: filtered.slice(0, ADVISORY_MAX_ITEMS),
    parsedCount,
    fetchedCount,
    filteredCount: filtered.length,
    errors,
    filteredByCveOnly
  };
}

async function fetchStatusFeeds() {
  const { items, parsedCount, fetchedCount, errors } = await fetchRssFeeds(statusFeeds);
  const sorted = items.sort((a, b) => new Date(b.dateISO || 0) - new Date(a.dateISO || 0));
  const mapped = sorted.map(mapStatusItem).filter(Boolean);
  return {
    items: mapped.slice(0, STATUS_MAX_ITEMS),
    parsedCount,
    fetchedCount,
    filteredCount: mapped.length,
    errors
  };
}

async function fetchRssFeeds(feeds) {
  const results = await Promise.all(
    feeds.map(async (feed) => {
      const response = await fetchFeed(feed.url);
      if (!response.ok) {
        return {
          items: [],
          parsedCount: 0,
          fetched: false,
          error: {
            sourceName: feed.sourceName,
            url: feed.url,
            status: response.status,
            message: response.message
          }
        };
      }
      try {
        const parsed = parseFeed(response.text, feed);
        return {
          items: parsed.items,
          parsedCount: parsed.items.length,
          fetched: true
        };
      } catch (error) {
        return {
          items: [],
          parsedCount: 0,
          fetched: true,
          error: {
            sourceName: feed.sourceName,
            url: feed.url,
            status: response.status,
            message: `Parse failed: ${error.message}`
          }
        };
      }
    })
  );
  const items = results.flatMap((result) => result.items);
  return {
    items: items.map(normalizeRssItem).filter(Boolean),
    fetchedCount: results.filter((result) => result.fetched).length,
    parsedCount: results.reduce((total, result) => total + (result.parsedCount || 0), 0),
    errors: results.flatMap((result) => (result.error ? [result.error] : []))
  };
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
    const filtered = normalized.filter(
      (item) => new Date(item.publishedISO || 0) >= new Date(since)
    );
    return {
      items: filtered,
      parsedCount: vulns.length,
      fetchedCount: 1,
      filteredCount: filtered.length,
      errors: []
    };
  } catch (error) {
    return {
      items: buildOsvFallback(ecosystem, since),
      parsedCount: 0,
      fetchedCount: 0,
      filteredCount: 0,
      errors: [
        {
          sourceName: `OSV ${ecosystem}`,
          url: baseUrl,
          status: null,
          message: error.message
        }
      ]
    };
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
  return [];
}

async function fetchFeed(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      return {
        ok: false,
        status: response.status,
        text: '',
        message: response.statusText || 'Request failed'
      };
    }
    return {
      ok: true,
      status: response.status,
      text: await response.text(),
      message: 'ok'
    };
  } catch (error) {
    return {
      ok: false,
      status: null,
      text: '',
      message: error.message
    };
  } finally {
    clearTimeout(timeout);
  }
}

function parseFeed(xmlText, feed) {
  const rssItems = parseRssItems(xmlText, feed);
  const atomItems = parseAtomEntries(xmlText, feed);
  return {
    items: [...rssItems, ...atomItems]
  };
}

function parseRssItems(xmlText, feed) {
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
    const contentRaw =
      getTagValue(itemBlock, 'content:encoded') ||
      getTagValue(itemBlock, 'content') ||
      '';
    const descriptionRaw =
      getTagValue(itemBlock, 'description') ||
      getTagValue(itemBlock, 'summary') ||
      contentRaw ||
      '';
    const summary = cleanFeedText(descriptionRaw);
    const content = cleanFeedText(contentRaw);
    const dateISO = normalizeDate(pubDate);

    items.push({
      title,
      url: link,
      dateISO,
      summary,
      content,
      sourceName: feed.sourceName,
      sourceType: feed.sourceType
    });
  }
  return items;
}

function parseAtomEntries(xmlText, feed) {
  const items = [];
  const entryRegex = /<entry>([\s\S]*?)<\/entry>/gi;
  let match;
  while ((match = entryRegex.exec(xmlText)) !== null) {
    const entryBlock = match[1];
    const title = getTagValue(entryBlock, 'title') || 'Security Update';
    const link = getAtomLink(entryBlock);
    const pubDate = getTagValue(entryBlock, 'published') || getTagValue(entryBlock, 'updated');
    const contentRaw =
      getTagValue(entryBlock, 'content') ||
      getTagValue(entryBlock, 'summary') ||
      '';
    const summaryRaw =
      getTagValue(entryBlock, 'summary') ||
      getTagValue(entryBlock, 'content') ||
      '';
    const summary = cleanFeedText(summaryRaw);
    const content = cleanFeedText(contentRaw);
    const dateISO = normalizeDate(pubDate);

    items.push({
      title,
      url: link,
      dateISO,
      summary,
      content,
      sourceName: feed.sourceName,
      sourceType: feed.sourceType
    });
  }
  return items;
}

function normalizeRssItem(item) {
  if (!item || !item.title) return null;
  const url = normalizeUrl(item.url);
  const summary = cleanFeedText(item.summary || item.content || '');
  const content = cleanFeedText(item.content || '');
  const textForExtraction = `${item.title} ${summary} ${content}`;
  const cves = extractCves(textForExtraction);
  const severity = scoreSeverity(textForExtraction);
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
  const lowerName = String(pkgName || '').toLowerCase();
  if (['sample-package', 'example-lib'].includes(lowerName)) {
    return null;
  }
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
    summary: cleanFeedText(item.summary || item.details || 'OSV vulnerability'),
    severity: extractOsvSeverity(item),
    publishedISO,
    aliases,
    url
  };
}

function extractOsvSeverity(item) {
  const cvssScore = extractCvssScore(item);
  if (Number.isFinite(cvssScore)) {
    return mapCvssScoreToSeverity(cvssScore);
  }
  const severityLabel = extractSeverityLabel(item);
  return severityLabel || 'UNKNOWN';
}

function extractCvssScore(item) {
  const candidates = [];
  if (Array.isArray(item?.severity)) {
    item.severity.forEach((entry) => {
      if (!entry) return;
      if (typeof entry === 'number' || typeof entry === 'string') {
        candidates.push(entry);
      } else if (entry.score) {
        candidates.push(entry.score);
      }
    });
  }
  if (item?.cvss?.score) candidates.push(item.cvss.score);
  if (item?.database_specific?.cvss?.score) candidates.push(item.database_specific.cvss.score);
  for (const value of candidates) {
    const numeric = Number.parseFloat(value);
    if (Number.isFinite(numeric)) return numeric;
  }
  return null;
}

function extractSeverityLabel(item) {
  if (Array.isArray(item?.severity) && item.severity.length) {
    const primary = item.severity[0];
    if (typeof primary === 'string') {
      return normalizeSeverityLabel(primary);
    }
    if (primary?.type && typeof primary.type === 'string') {
      return normalizeSeverityLabel(primary.type);
    }
  }
  return null;
}

function normalizeSeverityLabel(value) {
  const normalized = String(value || '').toUpperCase();
  if (normalized.includes('CRITICAL')) return 'CRITICAL';
  if (normalized.includes('HIGH')) return 'HIGH';
  if (normalized.includes('MEDIUM')) return 'MEDIUM';
  if (normalized.includes('LOW')) return 'LOW';
  return null;
}

function mapCvssScoreToSeverity(score) {
  if (score >= 9.0) return 'CRITICAL';
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}

function normalizeDate(value) {
  if (!value) return null;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString();
}

function decodeEntities(text) {
  return text
    .replace(/&nbsp;/g, ' ')
    .replace(/&#39;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function cleanFeedText(text) {
  if (!text) return '';
  return decodeEntities(String(text))
    .replace(/<[^>]*>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function getTagValue(block, tag) {
  const regex = new RegExp(`<${tag}(\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = regex.exec(block);
  if (!match) {
    return '';
  }
  return match[2].replace(/<!\\[CDATA\\[|\\]\\]>/g, '').trim();
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
    summary: cleanFeedText(item.summary),
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
    summary: cleanFeedText(item.summary)
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

function getAtomLink(block) {
  const linkMatch = block.match(/<link[^>]*?href=["']([^"']+)["'][^>]*?>/i);
  if (linkMatch) return linkMatch[1];
  return getTagValue(block, 'link') || '';
}

function buildResponse({
  type,
  items,
  timestamp,
  cached,
  sourceCount,
  fetchedCount,
  parsedCount,
  filteredCount,
  errors,
  filteredByCveOnly
}) {
  const response = {
    type,
    items,
    timestamp,
    cached,
    degraded: false,
    sourceCount
  };
  if (Number.isFinite(fetchedCount)) response.fetchedCount = fetchedCount;
  if (Number.isFinite(parsedCount)) response.parsedCount = parsedCount;
  if (Number.isFinite(filteredCount)) response.filteredCount = filteredCount;
  if (Array.isArray(errors)) response.errors = errors;
  if (filteredByCveOnly) response.filteredByCveOnly = true;
  return response;
}
