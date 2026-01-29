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
    sourceName: 'NVD Recent CVEs',
    sourceType: 'advisory',
    url: 'https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml'
  },
  {
    sourceName: 'Microsoft MSRC',
    sourceType: 'advisory',
    url: 'https://msrc.microsoft.com/update-guide/rss'
  },
  {
    sourceName: 'Cisco PSIRT',
    sourceType: 'advisory',
    url: 'https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml'
  },
  {
    sourceName: 'Cloudflare Security Blog',
    sourceType: 'advisory',
    url: 'https://blog.cloudflare.com/tag/security/rss/'
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

const osvFeeds = [
  {
    sourceName: 'GitHub Advisory Database',
    sourceType: 'osv',
    url: 'https://github.com/advisories.atom',
    atomAcceptFallback: true
  },
  {
    sourceName: 'OSV.dev (npm)',
    sourceType: 'osv',
    url: 'https://osv.dev/feeds/ecosystem/npm.atom'
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
  const refresh = req.query?.refresh === '1';
  const cveOnly = req.query?.cveOnly === '1' || req.query?.cveOnly === 'true';
  const debugMode = req.query?.debug === '1';
  const cacheKey = buildCacheKey(type, req.query || {});
  const now = Date.now();
  let cachedEntry = forceRefresh ? null : getCachedEntry(type, cacheKey, now);
  if (
    cachedEntry &&
    (refresh || debugMode) &&
    cachedEntry.items.length === 0 &&
    Array.isArray(cachedEntry.errors) &&
    cachedEntry.errors.length > 0
  ) {
    cachedEntry = null;
  }
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
        filteredByCveOnly: cachedEntry.filteredByCveOnly,
        debugMode
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
      const result = await fetchSupplyChainAdvisories({
        ecosystems,
        days: Number.isFinite(days) ? days : 30
      });
      items = result.items;
      fetchedCount = result.fetchedCount;
      parsedCount = result.parsedCount;
      filteredCount = result.filteredCount;
      errors = result.errors;
      sourceCount = osvFeeds.length;
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
        filteredByCveOnly,
        debugMode
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
  const sorted = mapped.sort(
    (a, b) => new Date(b.publishedISO || 0) - new Date(a.publishedISO || 0)
  );
  const filtered = cveOnly
    ? sorted.filter((item) => item.cves && item.cves.length > 0)
    : sorted;
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
      const response = await fetchFeed(feed.url, feed);
      if (!response.ok) {
        return {
          items: [],
          parsedCount: 0,
          fetched: false,
          error: {
            sourceName: feed.sourceName,
            url: feed.url,
            step: 'fetch',
            status: response.status,
            message: response.message
          }
        };
      }
      try {
        const parsed = parseFeed(response.text, feed);
        const normalization = normalizeFeedItems(parsed.items, feed);
        return {
          items: normalization.items,
          parsedCount: parsed.items.length,
          fetched: true,
          errors: normalization.errors
        };
      } catch (error) {
        return {
          items: [],
          parsedCount: 0,
          fetched: true,
          error: {
            sourceName: feed.sourceName,
            url: feed.url,
            step: 'parse',
            status: response.status,
            message: `Parse failed: ${error.message}`
          }
        };
      }
    })
  );
  const items = results.flatMap((result) => result.items);
  const normalizeErrors = results.flatMap((result) => result.errors || []);
  return {
    items,
    fetchedCount: results.filter((result) => result.fetched).length,
    parsedCount: results.reduce((total, result) => total + (result.parsedCount || 0), 0),
    errors: results
      .flatMap((result) => (result.error ? [result.error] : []))
      .concat(normalizeErrors)
  };
}

async function fetchSupplyChainAdvisories({ ecosystems, days }) {
  const lookbackMs = days * 24 * 60 * 60 * 1000;
  const since = new Date(Date.now() - lookbackMs);
  const ecosystemSet = new Set((ecosystems || []).map((eco) => eco.toLowerCase()));

  const results = await Promise.all(
    osvFeeds.map(async (feed) => {
      const response = await fetchFeed(feed.url, feed);
      if (!response.ok) {
        return {
          items: [],
          parsedCount: 0,
          fetched: false,
          error: {
            sourceName: feed.sourceName,
            url: feed.url,
            step: 'fetch',
            status: response.status,
            message: response.message
          }
        };
      }
      try {
        const parsed = parseFeed(response.text, feed);
        const normalized = [];
        const errors = [];
        parsed.items.forEach((item) => {
          try {
            const mapped = normalizeSupplyChainItem(item);
            if (mapped) normalized.push(mapped);
          } catch (error) {
            errors.push({
              sourceName: feed.sourceName,
              url: feed.url,
              step: 'normalize',
              status: response.status,
              message: `Normalize failed: ${error.message}`
            });
          }
        });
        return {
          items: normalized,
          parsedCount: parsed.items.length,
          fetched: true,
          errors
        };
      } catch (error) {
        return {
          items: [],
          parsedCount: 0,
          fetched: true,
          error: {
            sourceName: feed.sourceName,
            url: feed.url,
            step: 'parse',
            status: response.status,
            message: `Parse failed: ${error.message}`
          }
        };
      }
    })
  );

  const items = results.flatMap((result) => result.items);
  const normalized = items.filter((item) => {
    const published = new Date(item.publishedISO || 0);
    if (Number.isNaN(published.getTime()) || published < since) return false;
    if (!ecosystemSet.size) return true;
    return ecosystemSet.has(String(item.ecosystem || '').toLowerCase());
  });

  return {
    items: normalized,
    parsedCount: results.reduce((total, result) => total + (result.parsedCount || 0), 0),
    fetchedCount: results.filter((result) => result.fetched).length,
    filteredCount: normalized.length,
    errors: results
      .flatMap((result) => (result.error ? [result.error] : []))
      .concat(results.flatMap((result) => result.errors || []))
  };
}

const DEFAULT_FEED_HEADERS = {
  Accept:
    'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.8, text/html;q=0.7, */*;q=0.5',
  'User-Agent': 'CyberSecCommand/1.0 (Vercel; +https://<your-site-domain>)',
  'Accept-Language': 'en-US,en;q=0.9',
  'Cache-Control': 'no-cache'
};

async function fetchFeed(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const baseHeaders = {
      ...DEFAULT_FEED_HEADERS,
      ...(options.headers || {})
    };
    let response = await fetch(url, {
      signal: controller.signal,
      redirect: 'follow',
      headers: baseHeaders
    });
    if (response.status === 406 && options.atomAcceptFallback) {
      response = await fetch(url, {
        signal: controller.signal,
        redirect: 'follow',
        headers: {
          ...baseHeaders,
          Accept: 'application/atom+xml'
        }
      });
    }
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
  const feedType = detectFeedType(xmlText);
  const rssItems = feedType === 'rss' || feedType === 'both' ? parseRssItems(xmlText, feed) : [];
  const atomItems =
    feedType === 'atom' || feedType === 'both' ? parseAtomEntries(xmlText, feed) : [];
  return {
    items: [...rssItems, ...atomItems]
  };
}

function detectFeedType(xmlText) {
  const hasFeed = /<feed[\s>]/i.test(xmlText);
  const hasEntry = /<entry[\s>]/i.test(xmlText);
  const hasRss = /<rss[\s>]/i.test(xmlText);
  const hasChannel = /<channel[\s>]/i.test(xmlText);
  if ((hasFeed || hasEntry) && !(hasRss || hasChannel)) return 'atom';
  if ((hasRss || hasChannel) && !(hasFeed || hasEntry)) return 'rss';
  return 'both';
}

function parseRssItems(xmlText, feed) {
  const items = [];
  const itemRegex = /<item\b[^>]*>([\s\S]*?)<\/item>/gi;
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
  const entryRegex = /<entry\b[^>]*>([\s\S]*?)<\/entry>/gi;
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

function normalizeFeedItems(items, feed) {
  const normalized = [];
  const errors = [];
  items.forEach((item) => {
    try {
      const mapped = normalizeRssItem(item);
      if (mapped) normalized.push(mapped);
    } catch (error) {
      errors.push({
        sourceName: feed.sourceName,
        url: feed.url,
        step: 'normalize',
        status: null,
        message: `Normalize failed: ${error.message}`
      });
    }
  });
  return { items: normalized, errors };
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

function normalizeSupplyChainItem(item) {
  if (!item || !item.title) return null;
  const combined = `${item.title} ${item.summary || ''} ${item.content || ''}`;
  const metadata = extractSupplyChainMetadata(combined);
  const pkgName = metadata.packageName || item.title || 'Unknown';
  const eco = metadata.ecosystem || 'Unknown';
  const publishedISO = item.dateISO || new Date().toISOString();
  const lowerName = String(pkgName || '').toLowerCase();
  if (['sample-package', 'example-lib'].includes(lowerName)) {
    return null;
  }
  const aliases = Array.from(
    new Set([...(metadata.aliases || []), ...extractCves(combined)])
  );
  return {
    id: createId(item.url || `${eco}-${pkgName}-${publishedISO}`),
    ecosystem: eco,
    package: pkgName,
    summary: cleanFeedText(item.summary || item.content || 'Supply chain advisory'),
    severity: metadata.severity || 'UNKNOWN',
    publishedISO,
    aliases,
    url: normalizeUrl(item.url)
  };
}

function extractSupplyChainMetadata(text) {
  const cleaned = cleanFeedText(text || '');
  const packageMatch = cleaned.match(/Package:\s*([^\n]+)/i);
  const ecosystemMatch = cleaned.match(/Ecosystem:\s*([^\n]+)/i);
  const severityMatch = cleaned.match(/Severity:\s*([^\n]+)/i);
  const severityHintMatch = cleaned.match(/\b(critical|high|medium|low)\b/i);
  const titlePackageMatch = cleaned.match(/\s+in\s+([A-Za-z0-9_.-]+)\b/i);
  const ghsaMatch = cleaned.match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i);
  const packageName =
    cleanFeedText(packageMatch?.[1] || '') || cleanFeedText(titlePackageMatch?.[1] || '');
  const ecosystem = cleanFeedText(ecosystemMatch?.[1] || '');
  const severity =
    normalizeSeverityLabel(severityMatch?.[1] || '') ||
    normalizeSeverityLabel(severityHintMatch?.[1] || '') ||
    null;
  const aliases = [];
  if (ghsaMatch?.[0]) aliases.push(ghsaMatch[0].toUpperCase());
  return {
    packageName: packageName || null,
    ecosystem: ecosystem || null,
    severity,
    aliases
  };
}

function normalizeSeverityLabel(value) {
  const normalized = String(value || '').toUpperCase();
  if (normalized.includes('CRITICAL')) return 'CRITICAL';
  if (normalized.includes('HIGH')) return 'HIGH';
  if (normalized.includes('MEDIUM')) return 'MEDIUM';
  if (normalized.includes('LOW')) return 'LOW';
  return null;
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
  return match[2].replace(/<!\[CDATA\[|\]\]>/g, '').trim();
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
  const links = [];
  const linkRegex = /<link\s+([^>]*?)\/?>/gi;
  let match;
  while ((match = linkRegex.exec(block)) !== null) {
    const attrs = match[1];
    const hrefMatch = attrs.match(/href=["']([^"']+)["']/i);
    if (!hrefMatch) continue;
    const relMatch = attrs.match(/rel=["']([^"']+)["']/i);
    links.push({ href: hrefMatch[1], rel: relMatch ? relMatch[1] : '' });
  }
  const preferred = links.find((link) => !link.rel || link.rel === 'alternate');
  if (preferred) return preferred.href;
  if (links.length) return links[0].href;
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
  filteredByCveOnly,
  debugMode
}) {
  const errorCount = Array.isArray(errors) ? errors.length : 0;
  const noItemsFetched =
    Number.isFinite(fetchedCount) &&
    Number.isFinite(parsedCount) &&
    fetchedCount === 0 &&
    parsedCount === 0;
  const degraded = errorCount > 0 || noItemsFetched;
  const response = {
    type,
    items,
    timestamp,
    cached,
    degraded,
    sourceCount
  };
  if (Number.isFinite(fetchedCount)) response.fetchedCount = fetchedCount;
  if (Number.isFinite(parsedCount)) response.parsedCount = parsedCount;
  if (Number.isFinite(filteredCount)) response.filteredCount = filteredCount;
  if (Array.isArray(errors)) response.errors = errors;
  if (filteredByCveOnly) response.filteredByCveOnly = true;
  if (debugMode) {
    response.debug = buildDebugInfo({
      type,
      cached,
      timestamp,
      sourceCount,
      fetchedCount,
      parsedCount,
      errors,
      items,
      degraded
    });
  }
  return response;
}

function buildDebugInfo({
  type,
  cached,
  timestamp,
  sourceCount,
  fetchedCount,
  parsedCount,
  errors,
  items,
  degraded
}) {
  const titles = (items || [])
    .map((item) => item?.title || item?.package || item?.summary || '')
    .filter(Boolean)
    .slice(0, 5);
  return {
    type,
    cached,
    timestamp,
    sourceCount,
    fetchedCount,
    parsedCount,
    degraded,
    errors: Array.isArray(errors) ? errors : [],
    sampleTitles: titles
  };
}
