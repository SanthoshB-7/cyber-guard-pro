const verifiedCacheTtlMs = 24 * 60 * 60 * 1000;
const liveCacheTtlMs = 45 * 60 * 1000;
const rssSources = [
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', type: 'news' },
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', type: 'news' },
  { name: 'Cloudflare Status', url: 'https://www.cloudflarestatus.com/history.rss', type: 'status' },
  { name: 'Google Cloud Status', url: 'https://status.cloud.google.com/feed.atom', type: 'status' },
  { name: 'Microsoft 365 Status', url: 'https://status.office365.com/api/v2.0/incidents/feed?format=rss', type: 'status' },
  { name: 'GitHub Status', url: 'https://www.githubstatus.com/history.rss', type: 'status' },
  { name: 'CISA Advisories', url: 'https://www.cisa.gov/cybersecurity-advisories/rss.xml', type: 'official' }
];
const wikiPageTitle = 'List_of_data_breaches';
let verifiedCache = null;
let liveCache = null;

export default async function handler(req, res) {
  const timestamp = new Date().toISOString();
  const requestedMode = (req.query?.mode || 'verified').toLowerCase();
  const mode = requestedMode === 'live' ? 'live' : 'verified';

  if (mode === 'verified') {
    try {
      const verifiedResult = await fetchVerifiedBreaches();
      if (verifiedResult?.breaches?.length) {
        const responsePayload = {
          breaches: verifiedResult.breaches,
          timestamp,
          source: 'wikipedia',
          mode: 'verified'
        };
        verifiedCache = {
          ...responsePayload,
          cachedAt: Date.now()
        };
        res.setHeader('Content-Type', 'application/json');
        res.status(200).json(responsePayload);
        return;
      }
    } catch (error) {
      console.warn('Verified dataset unavailable:', error.message);
    }
  }

  const liveResult = await fetchLiveBreaches();
  if (liveResult?.breaches?.length) {
    const responsePayload = {
      breaches: liveResult.breaches,
      timestamp,
      source: 'intelligence_feed',
      mode: 'live'
    };
    liveCache = {
      ...responsePayload,
      cachedAt: Date.now()
    };
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(responsePayload);
    return;
  }

  res.setHeader('Content-Type', 'application/json');
  const cache = mode === 'verified' ? verifiedCache : liveCache;
  const cacheTtl = mode === 'verified' ? verifiedCacheTtlMs : liveCacheTtlMs;
  if (cache && Date.now() - cache.cachedAt <= cacheTtl) {
    res.status(200).json({
      breaches: cache.breaches,
      timestamp,
      source: cache.source,
      mode: cache.mode,
      stale: true
    });
    return;
  }

  res.status(503).json({
    error: 'Breach sources unavailable',
    timestamp,
    source: 'unavailable',
    mode,
    stale: true
  });
}

const fallbackBreaches = [
  {
    name: 'Qantas Airways',
    date: '2025-10-11',
    recordsAffected: 5700000,
    dataExposed: 'Customer Data',
    description: 'Unauthorized access to customer data systems reported by Qantas.',
    source: 'Fallback'
  },
  {
    name: 'Red Hat',
    date: '2025-10-15',
    recordsAffected: 570000000,
    dataExposed: 'Source Code & Credentials',
    description: 'Data exposure involving source repositories and credentials.',
    source: 'Fallback'
  },
  {
    name: 'TransUnion',
    date: '2025-07-30',
    recordsAffected: 4400000,
    dataExposed: 'Personal Information',
    description: 'Incident impacting customer records reported by TransUnion.',
    source: 'Fallback'
  },
  {
    name: 'Google/Salesforce',
    date: '2025-08-15',
    recordsAffected: 2500000000,
    dataExposed: 'Email Accounts',
    description: 'Large credential exposure impacting email accounts.',
    source: 'Fallback'
  },
  {
    name: 'Infostealer Log',
    date: '2025-10-21',
    recordsAffected: 183000000,
    dataExposed: 'Credentials',
    description: 'Infostealer log leak affecting multiple services.',
    source: 'Fallback'
  }
];

function extractBreachList(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.data)) return payload.data;
  if (Array.isArray(payload?.breaches)) return payload.breaches;
  if (Array.isArray(payload?.result)) return payload.result;
  if (Array.isArray(payload?.items)) return payload.items;
  if (Array.isArray(payload?.rows)) return payload.rows;
  if (Array.isArray(payload?.data?.breaches)) return payload.data.breaches;
  if (Array.isArray(payload?.data?.items)) return payload.data.items;
  if (Array.isArray(payload?.data?.rows)) return payload.data.rows;
  if (Array.isArray(payload?.result?.breaches)) return payload.result.breaches;
  return [];
}

function normalizeBreach(breach) {
  const recordsAffected =
    breach.records_affected ??
    breach.num_records ??
    breach.recordsAffected ??
    breach.records ??
    0;
  return {
    name: breach.name || breach.title || breach.company || 'Unknown',
    date:
      breach.date_discovered ||
      breach.breach_date ||
      breach.date ||
      breach.discovered ||
      new Date().toISOString().split('T')[0],
    recordsAffected,
    dataExposed: breach.data_exposed || breach.compromised_data || breach.data || '',
    description: breach.description || breach.summary || 'Data breach incident',
    severity: calculateSeverity(Number(recordsAffected) || 0),
    source: breach.source || 'Breach Directory',
    url: breach.url || breach.link || '',
    category: breach.category || 'breach',
    sourceName: breach.sourceName || 'Breach Directory',
    attackType: breach.attackType || 'Unknown'
  };
}

function calculateSeverity(recordCount) {
  if (recordCount > 1000000) return 'CRITICAL';
  if (recordCount > 100000) return 'HIGH';
  if (recordCount > 10000) return 'MEDIUM';
  return 'LOW';
}

function sortBreachesByDate(breaches) {
  return [...breaches].sort((a, b) => {
    const timeA = Date.parse(a.date) || 0;
    const timeB = Date.parse(b.date) || 0;
    return timeB - timeA;
  });
}

async function fetchVerifiedBreaches() {
  const cacheValid = verifiedCache && Date.now() - verifiedCache.cachedAt <= verifiedCacheTtlMs;
  if (cacheValid) {
    return { breaches: verifiedCache.breaches };
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);
  let response;
  try {
    const url = `https://en.wikipedia.org/w/api.php?action=parse&page=${wikiPageTitle}&prop=text&format=json&origin=*`;
    response = await fetch(url, {
      headers: {
        accept: 'application/json',
        'user-agent': 'CyberSecCommand'
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new Error('Wikipedia API error');
  }

  const payload = await response.json();
  const html = payload?.parse?.text?.['*'] || '';
  const items = parseWikipediaBreaches(html);
  const deduped = dedupeBreaches(items);
  return {
    breaches: sortBreachesByDate(deduped).slice(0, 50)
  };
}

async function fetchLiveBreaches() {
  const cacheValid = liveCache && Date.now() - liveCache.cachedAt <= liveCacheTtlMs;
  if (cacheValid) {
    return { breaches: liveCache.breaches };
  }

  const collected = [];
  for (const source of rssSources) {
    try {
      const rssResponse = await fetchWithTimeout(source.url, {
        headers: {
          accept: 'application/rss+xml, application/xml, text/xml',
          'user-agent': 'CyberSecCommand'
        }
      });
      if (!rssResponse.ok) {
        throw new Error(`RSS error from ${source.url}`);
      }
      const xmlText = await rssResponse.text();
      const items = parseFeedItems(xmlText, source);
      const normalized = items
        .map(item => normalizeLiveItem(item))
        .filter(item => item);
      collected.push(...normalized);
    } catch (error) {
      console.warn('RSS source failed:', source.url, error.message);
    }
  }

  if (!collected.length) {
    return { breaches: [] };
  }

  const filtered = applyLiveFilters(collected);
  return {
    breaches: sortBreachesByDate(filtered).slice(0, 50)
  };
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeoutId);
  }
}

function parseFeedItems(xmlText, source) {
  const rssItems = xmlText.match(/<item[\s\S]*?<\/item>/gi) || [];
  const atomEntries = xmlText.match(/<entry[\s\S]*?<\/entry>/gi) || [];
  const parsedItems = rssItems.map(item => ({
    title: extractRssField(item, 'title'),
    link: extractRssField(item, 'link'),
    pubDate: extractRssField(item, 'pubDate'),
    description: extractRssField(item, 'description') || extractRssField(item, 'content:encoded'),
    sourceName: source.name,
    sourceType: source.type
  }));
  const parsedEntries = atomEntries.map(entry => ({
    title: extractRssField(entry, 'title'),
    link: extractAtomLink(entry),
    pubDate: extractRssField(entry, 'published') || extractRssField(entry, 'updated'),
    description: extractRssField(entry, 'summary') || extractRssField(entry, 'content'),
    sourceName: source.name,
    sourceType: source.type
  }));
  return [...parsedItems, ...parsedEntries];
}

function extractRssField(item, tag) {
  const regex = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = item.match(regex);
  if (!match) return '';
  return stripCdata(match[1]).trim();
}

function extractAtomLink(entry) {
  const hrefMatch = entry.match(/<link[^>]*href=["']([^"']+)["'][^>]*>/i);
  if (hrefMatch && hrefMatch[1]) return hrefMatch[1].trim();
  return extractRssField(entry, 'link');
}

function stripCdata(value) {
  return value.replace(/^<!\\[CDATA\\[|\\]\\]>$/g, '');
}

function stripHtml(value) {
  return value.replace(/<[^>]*>/g, '').replace(/\\s+/g, ' ').trim();
}

function normalizeLiveItem(item) {
  const title = stripHtml(item.title || 'Untitled incident');
  const summary = stripHtml(item.description || '');
  const pubDate = item.pubDate ? new Date(item.pubDate) : null;
  const date = pubDate && !Number.isNaN(pubDate.getTime())
    ? pubDate.toISOString()
    : new Date().toISOString();
  const category = classifyLiveCategory(title, summary, item.sourceType);

  if (!category) {
    return null;
  }

  const severityScore = scoreLiveSeverity({
    title,
    summary,
    category,
    sourceType: item.sourceType,
    sourceName: item.sourceName
  });
  const attackType = inferAttackType(title, summary);
  const recordsAffected = parseRecordCount(`${title} ${summary}`) || 'Unknown';

  return {
    name: title,
    date,
    url: item.link || '',
    recordsAffected,
    dataExposed: 'Not disclosed',
    description: summary,
    severity: severityFromScore(severityScore),
    category,
    sourceName: item.sourceName || 'Intelligence Feed',
    attackType
  };
}

function applyLiveFilters(items) {
  return items.filter(item => {
    if (!item) return false;
    if (isLowSignalItem(item)) return false;
    if (hasExcludedTerms(item)) return false;
    if (item.category === 'incident') {
      return isMajorIncident(item) || isOfficialSource(item.sourceName);
    }
    return isConfirmedLiveItem(item);
  });
}

function classifyLiveCategory(title, summary, sourceType) {
  const text = `${title} ${summary}`.toLowerCase();
  const ransomwareMatch = ransomwareKeywords.some(keyword => text.includes(keyword));
  const breachMatch = breachKeywords.some(keyword => text.includes(keyword));
  const incidentMatch = incidentKeywords.some(keyword => text.includes(keyword));

  if (ransomwareMatch) return 'ransomware';
  if (breachMatch) return 'breach';
  if (incidentMatch || sourceType === 'status') return 'incident';
  return null;
}

function scoreLiveSeverity({ title, summary, category, sourceType, sourceName }) {
  const text = `${title} ${summary}`.toLowerCase();
  let score = 0;
  if (category === 'ransomware') score += 4;
  if (category === 'breach') score += 3;
  if (category === 'incident') score += 2;

  if (['ransomware', 'extortion', 'stolen', 'exfiltration', 'leak'].some(term => text.includes(term))) {
    score += 2;
  }
  if (['major outage', 'widespread', 'global', 'multi-region'].some(term => text.includes(term))) {
    score += 2;
  }
  if (['zero-day exploited', 'actively exploited'].some(term => text.includes(term))) {
    score += 2;
  }
  if (['million', 'records', 'customers', 'users', 'ssn', 'passwords'].some(term => text.includes(term))) {
    score += 2;
  }
  if (sourceType === 'status') {
    score += 2;
  }
  if (sourceType === 'official' || isOfficialSource(sourceName)) {
    score += 2;
  }

  return score;
}

function severityFromScore(score) {
  if (score >= 8) return 'CRITICAL';
  if (score >= 6) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

function isLowSignalItem(item) {
  const text = `${item.name} ${item.description}`.toLowerCase();
  return lowSignalKeywords.some(keyword => text.includes(keyword));
}

function isMajorIncident(item) {
  const text = `${item.name} ${item.description}`.toLowerCase();
  return majorIncidentKeywords.some(keyword => text.includes(keyword));
}

function isOfficialSource(sourceName) {
  if (!sourceName) return false;
  const name = sourceName.toLowerCase();
  return name.includes('status') || name.includes('cisa');
}

const breachKeywords = [
  'breach', 'leaked', 'leak', 'exposed', 'exposure', 'stolen data',
  'data exposed', 'compromise', 'compromised', 'exfiltrat', 'unauthorized access'
];

const ransomwareKeywords = [
  'ransomware', 'extortion', 'data leak site', 'lockbit', 'alphv', 'blackcat',
  'cl0p', 'ransomhub', '8base', 'akira', 'inc ransom', 'medusa', 'play',
  'royal'
];

const incidentKeywords = [
  'outage', 'incident', 'degraded', 'disruption', 'service issue',
  'latency', 'elevated errors', 'partial outage', 'major outage'
];

const majorIncidentKeywords = [
  'outage', 'incident', 'degraded', 'elevated errors', 'partial outage',
  'major outage', 'widespread', 'global', 'multi-region'
];

const lowSignalKeywords = [
  'patch tuesday', 'how to', 'tutorial', 'tips', 'guide', 'update',
  'release', 'preview', 'webinar', 'podcast', 'product launch', 'explainer'
];

const excludeKeywords = [
  'denies', 'denied', 'alleged', 'claims', 'rumored', 'unconfirmed',
  'possible', 'might', 'suspected', 'no evidence'
];

const confirmationKeywords = [
  'confirmed', 'discloses', 'disclosed', 'breach notification', 'regulator',
  'sec', 'settlement', 'investigation found', 'data exposed'
];

const attackTypeKeywords = [
  { type: 'ransomware/extortion', keywords: ['ransomware', 'extortion', 'data leak site', 'lockbit', 'alphv', 'blackcat', 'cl0p', 'ransomhub', '8base', 'akira', 'medusa', 'play', 'royal'] },
  { type: 'misconfiguration/exposed database', keywords: ['misconfiguration', 'exposed database', 'open database', 'publicly accessible'] },
  { type: 'credential stuffing', keywords: ['credential stuffing', 'password spray'] },
  { type: 'phishing', keywords: ['phishing', 'spearphishing'] },
  { type: 'supply chain', keywords: ['supply chain', 'third-party'] },
  { type: 'insider', keywords: ['insider', 'employee'] },
  { type: 'third-party vendor', keywords: ['vendor', 'third-party', 'service provider'] }
];

function parseWikipediaBreaches(html) {
  const tables = html.match(/<table[^>]*class="[^"]*wikitable[^"]*"[\s\S]*?<\/table>/gi) || [];
  const items = [];

  tables.forEach(table => {
    const rows = table.match(/<tr[\s\S]*?<\/tr>/gi) || [];
    rows.forEach(row => {
      const cells = row.match(/<td[\s\S]*?<\/td>/gi);
      if (!cells || cells.length < 2) return;
      const textCells = cells.map(cell => stripHtml(cell).replace(/\[[^\]]+\]/g, '').trim());
      const linkMatch = row.match(/<a[^>]+href="([^"]+)"[^>]*>/i);
      const url = linkMatch ? `https://en.wikipedia.org${linkMatch[1]}` : '';

      const dateText = textCells[0];
      const name = textCells[1] || 'Unknown';
      const recordsText = textCells[2] || '';
      const description = textCells.slice(3).join(' ').trim() || textCells[2] || 'Reported breach incident';
      const date = parseDateFromText(dateText);
      if (!date || !name) return;

      const recordsAffected = parseRecordCount(recordsText) || parseRecordCount(description) || 'Unknown';
      const attackType = inferAttackType(name, description);
      items.push({
        name,
        date,
        url,
        recordsAffected,
        dataExposed: 'Unknown',
        description,
        severity: severityFromScore(recordsAffected !== 'Unknown' ? scoreSeverityByRecords(recordsAffected) : 4),
        category: 'breach',
        attackType,
        sourceName: 'Wikipedia'
      });
    });
  });

  return items;
}

function parseDateFromText(value) {
  if (!value) return null;
  const trimmed = value.trim();
  const parsed = Date.parse(trimmed);
  if (!Number.isNaN(parsed)) return new Date(parsed).toISOString();
  const yearMatch = trimmed.match(/\b(19|20)\d{2}\b/);
  if (yearMatch) {
    return new Date(`${yearMatch[0]}-01-01`).toISOString();
  }
  return null;
}

function dedupeBreaches(items) {
  const seen = new Set();
  return items.filter(item => {
    const key = `${item.name.toLowerCase()}-${item.date.split('T')[0]}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function parseRecordCount(text) {
  if (!text) return null;
  const normalized = text.toLowerCase().replace(/,/g, '');
  const match = normalized.match(/(\d+(?:\.\d+)?)\s*(million|billion|bn|m|k)?/i);
  if (!match) return null;
  const value = Number(match[1]);
  if (Number.isNaN(value)) return null;
  const unit = match[2];
  if (!unit) return Math.round(value);
  if (unit === 'billion' || unit === 'bn') return Math.round(value * 1_000_000_000);
  if (unit === 'million' || unit === 'm') return Math.round(value * 1_000_000);
  if (unit === 'k') return Math.round(value * 1_000);
  return Math.round(value);
}

function inferAttackType(title, summary) {
  const text = `${title} ${summary}`.toLowerCase();
  for (const group of attackTypeKeywords) {
    if (group.keywords.some(keyword => text.includes(keyword))) {
      return group.type;
    }
  }
  return 'Unknown';
}

function scoreSeverityByRecords(records) {
  if (typeof records !== 'number') return 4;
  if (records > 1_000_000) return 8;
  if (records > 100_000) return 6;
  if (records > 10_000) return 4;
  return 3;
}

function hasExcludedTerms(item) {
  const text = `${item.name} ${item.description}`.toLowerCase();
  return excludeKeywords.some(keyword => text.includes(keyword));
}

function isConfirmedLiveItem(item) {
  if (item.category !== 'breach' && item.category !== 'ransomware') return true;
  const text = `${item.name} ${item.description}`.toLowerCase();
  return confirmationKeywords.some(keyword => text.includes(keyword));
}
