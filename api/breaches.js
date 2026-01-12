const cacheTtlMs = 6 * 60 * 60 * 1000;
const rssSources = [
  'https://www.bleepingcomputer.com/feed/',
  'https://feeds.feedburner.com/TheHackersNews'
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
        stale: false
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

  try {
    const rssResult = await fetchRssBreaches();
    if (rssResult?.breaches?.length) {
      const responsePayload = {
        breaches: rssResult.breaches,
        timestamp,
        source: 'rss',
        stale: false
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
    console.warn('RSS feed unavailable:', error.message);
  }

  res.setHeader('Content-Type', 'application/json');
  if (breachCache && Date.now() - breachCache.cachedAt <= cacheTtlMs) {
    res.status(200).json({
      breaches: breachCache.breaches,
      timestamp,
      source: breachCache.source,
      stale: true
    });
    return;
  }

  res.status(503).json({
    error: 'Breach sources unavailable',
    timestamp,
    source: 'unavailable',
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
    url: breach.url || breach.link || ''
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
  const formattedBreaches = (Array.isArray(breachList) ? breachList : []).map(breach => normalizeBreach(breach));
  return {
    breaches: sortBreachesByDate(formattedBreaches).slice(0, 50)
  };
}

async function fetchRssBreaches() {
  let lastError = null;

  for (const source of rssSources) {
    try {
      const rssResponse = await fetchWithTimeout(source, {
        headers: {
          accept: 'application/rss+xml, application/xml, text/xml',
          'user-agent': 'CyberSecCommand'
        }
      });
      if (!rssResponse.ok) {
        throw new Error(`RSS error from ${source}`);
      }
      const xmlText = await rssResponse.text();
      const items = parseRssItems(xmlText);
      const normalized = items.map(item => normalizeRssBreach(item));
      if (normalized.length) {
        return {
          breaches: sortBreachesByDate(normalized).slice(0, 50)
        };
      }
    } catch (error) {
      lastError = error;
      console.warn('RSS source failed:', source, error.message);
    }
  }

  throw lastError || new Error('RSS sources unavailable');
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

function parseRssItems(xmlText) {
  const items = xmlText.match(/<item[\s\S]*?<\/item>/gi) || [];
  return items.map(item => ({
    title: extractRssField(item, 'title'),
    link: extractRssField(item, 'link'),
    pubDate: extractRssField(item, 'pubDate'),
    description: extractRssField(item, 'description') || extractRssField(item, 'content:encoded')
  }));
}

function extractRssField(item, tag) {
  const regex = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = item.match(regex);
  if (!match) return '';
  return stripCdata(match[1]).trim();
}

function stripCdata(value) {
  return value.replace(/^<!\\[CDATA\\[|\\]\\]>$/g, '');
}

function stripHtml(value) {
  return value.replace(/<[^>]*>/g, '').replace(/\\s+/g, ' ').trim();
}

function normalizeRssBreach(item) {
  const title = stripHtml(item.title || 'Untitled incident');
  const description = stripHtml(item.description || '');
  const pubDate = item.pubDate ? new Date(item.pubDate) : null;
  const date = pubDate && !Number.isNaN(pubDate.getTime())
    ? pubDate.toISOString()
    : new Date().toISOString();
  const severity = getRssSeverity(title);
  return {
    name: title,
    date,
    recordsAffected: 0,
    dataExposed: 'Not disclosed',
    description,
    severity,
    source: 'RSS Feed',
    url: item.link || ''
  };
}

function getRssSeverity(title) {
  const normalizedTitle = title.toLowerCase();
  if (normalizedTitle.includes('critical')) {
    return 'CRITICAL';
  }
  if (['ransomware', 'breach', 'leak', 'stolen'].some(term => normalizedTitle.includes(term))) {
    return 'HIGH';
  }
  return 'MEDIUM';
}
