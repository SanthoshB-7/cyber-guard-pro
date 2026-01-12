const cacheTtlMs = 45 * 60 * 1000;
const rssSources = [
  { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/', type: 'news' },
  { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews', type: 'news' },
  { name: 'Cloudflare Status', url: 'https://www.cloudflarestatus.com/history.rss', type: 'status' },
  { name: 'Google Cloud Status', url: 'https://status.cloud.google.com/feed.atom', type: 'status' },
  { name: 'Microsoft 365 Status', url: 'https://status.office365.com/api/v2.0/incidents/feed?format=rss', type: 'status' },
  { name: 'GitHub Status', url: 'https://www.githubstatus.com/history.rss', type: 'status' },
  { name: 'CISA Advisories', url: 'https://www.cisa.gov/cybersecurity-advisories/rss.xml', type: 'official' }
];
let breachCache = null;

export default async function handler(req, res) {
  const timestamp = new Date().toISOString();
  try {
    const breachDirectoryResult = await fetchBreachDirectory();
    if (breachDirectoryResult?.breaches?.length) {
      const responsePayload = {
        breaches: breachDirectoryResult.breaches,
        timestamp,
        source: 'breachdirectory',
        stale: false,
        registryAvailable: true
      };
      breachCache = {
        ...responsePayload,
        cachedAt: Date.now()
      };
      res.setHeader('Content-Type', 'application/json');
      res.status(200).json(responsePayload);
      return;
    }
  } catch (error) {
    console.warn('Breach Directory unavailable:', error.message);
  }

  const rssResult = await fetchRssBreaches();
  if (rssResult?.breaches?.length) {
    const responsePayload = {
      breaches: rssResult.breaches,
      timestamp,
      source: 'intelligence_feed',
      stale: false,
      registryAvailable: false
    };
    breachCache = {
      ...responsePayload,
      cachedAt: Date.now()
    };
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(responsePayload);
    return;
  }

  res.setHeader('Content-Type', 'application/json');
  if (breachCache && Date.now() - breachCache.cachedAt <= cacheTtlMs) {
    res.status(200).json({
      breaches: breachCache.breaches,
      timestamp,
      source: breachCache.source,
      stale: true,
      registryAvailable: breachCache.registryAvailable ?? false
    });
    return;
  }

  res.status(503).json({
    error: 'Breach sources unavailable',
    timestamp,
    source: 'unavailable',
    stale: true,
    registryAvailable: false
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
    sourceName: breach.sourceName || 'Breach Directory'
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

async function fetchBreachDirectory() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000);

  let breachResponse;
  try {
    breachResponse = await fetch('https://breachdirectory.org/api/v1/breach', {
      headers: {
        accept: 'application/json',
        'user-agent': 'CyberSecCommand'
      },
      signal: controller.signal
    });
  } finally {
    clearTimeout(timeoutId);
  }

  if (!breachResponse.ok) {
    throw new Error('Breach API error');
  }

  const breachData = await breachResponse.json();
  const breachList = extractBreachList(breachData);
  const formattedBreaches = (Array.isArray(breachList) ? breachList : []).map(breach => normalizeBreach({
    ...breach,
    category: 'breach',
    sourceName: 'Breach Directory'
  }));
  return {
    breaches: sortBreachesByDate(formattedBreaches).slice(0, 50)
  };
}

async function fetchRssBreaches() {
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
        .map(item => normalizeRssBreach(item))
        .filter(item => item);
      collected.push(...normalized);
    } catch (error) {
      console.warn('RSS source failed:', source.url, error.message);
    }
  }

  if (!collected.length) {
    return { breaches: [] };
  }

  const filtered = applyRssFilters(collected);
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

function normalizeRssBreach(item) {
  const title = stripHtml(item.title || 'Untitled incident');
  const summary = stripHtml(item.description || '');
  const pubDate = item.pubDate ? new Date(item.pubDate) : null;
  const date = pubDate && !Number.isNaN(pubDate.getTime())
    ? pubDate.toISOString()
    : new Date().toISOString();
  const category = classifyRssCategory(title, summary, item.sourceType);

  if (!category) {
    return null;
  }

  const severityScore = scoreRssSeverity({
    title,
    summary,
    category,
    sourceType: item.sourceType,
    sourceName: item.sourceName
  });

  return {
    name: title,
    date,
    url: item.link || '',
    recordsAffected: 'Unknown',
    dataExposed: 'Not disclosed',
    description: summary,
    severity: severityFromScore(severityScore),
    category,
    sourceName: item.sourceName || 'Intelligence Feed'
  };
}

function applyRssFilters(items) {
  return items.filter(item => {
    if (!item) return false;
    if (isLowSignalItem(item)) return false;
    if (item.category === 'incident') {
      return isMajorIncident(item) || isOfficialSource(item.sourceName);
    }
    return item.category === 'ransomware' || item.category === 'breach';
  });
}

function classifyRssCategory(title, summary, sourceType) {
  const text = `${title} ${summary}`.toLowerCase();
  const ransomwareMatch = ransomwareKeywords.some(keyword => text.includes(keyword));
  const breachMatch = breachKeywords.some(keyword => text.includes(keyword));
  const incidentMatch = incidentKeywords.some(keyword => text.includes(keyword));

  if (ransomwareMatch) return 'ransomware';
  if (breachMatch) return 'breach';
  if (incidentMatch || sourceType === 'status') return 'incident';
  return null;
}

function scoreRssSeverity({ title, summary, category, sourceType, sourceName }) {
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
