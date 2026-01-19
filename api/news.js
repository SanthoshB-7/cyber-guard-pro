const CACHE_TTL_MS = 15 * 60 * 1000;
const CACHE_HEADER = 's-maxage=900, stale-while-revalidate=300';
const MAX_ITEMS = 100;

const feeds = [
  {
    sourceName: 'CISA Advisories',
    sourceType: 'official',
    url: 'https://www.cisa.gov/news-events/cybersecurity-advisories.xml'
  },
  {
    sourceName: 'CISA Alerts',
    sourceType: 'official',
    url: 'https://www.cisa.gov/news-events/alerts.xml'
  },
  {
    sourceName: 'BleepingComputer',
    sourceType: 'news',
    url: 'https://www.bleepingcomputer.com/feed/'
  },
  {
    sourceName: 'The Hacker News',
    sourceType: 'news',
    url: 'https://feeds.feedburner.com/TheHackersNews'
  },
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

let cache = {
  timestamp: 0,
  items: []
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
  if (cache.items.length && now - cache.timestamp < CACHE_TTL_MS) {
    return res.status(200).json({ items: cache.items, cached: true });
  }

  try {
    const results = await Promise.all(
      feeds.map(async (feed) => {
        const xmlText = await fetchFeed(feed.url);
        if (!xmlText) return [];
        return parseFeed(xmlText, feed);
      })
    );

    const rawItems = results.flat();
    const normalized = rawItems.map(normalizeItem).filter(Boolean);
    const deduped = dedupeItems(normalized);
    const clustered = clusterItems(deduped);
    const sorted = clustered
      .sort((a, b) => new Date(b.dateISO || 0) - new Date(a.dateISO || 0))
      .slice(0, MAX_ITEMS);
    const sanitized = sorted.map(stripInternalFields);

    cache = {
      timestamp: now,
      items: sanitized
    };

    return res.status(200).json({ items: sanitized, cached: false });
  } catch (error) {
    return res.status(500).json({ error: 'News API failed', details: error.message });
  }
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
    const pubDate = getTagValue(itemBlock, 'pubDate') || getTagValue(itemBlock, 'dc:date') || getTagValue(itemBlock, 'updated');
    const descriptionRaw = getTagValue(itemBlock, 'description') || getTagValue(itemBlock, 'content:encoded') || '';
    const summary = stripHtml(descriptionRaw).slice(0, 240);
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

function normalizeItem(item) {
  if (!item || !item.title) return null;
  const url = normalizeUrl(item.url);
  const summary = item.summary || '';
  const cves = extractCves(`${item.title} ${summary}`);
  const tags = extractTags(`${item.title} ${summary}`, item.sourceType);
  const { severity, score } = scoreSeverity(`${item.title} ${summary}`, item.sourceType);
  const dateISO = item.dateISO || new Date().toISOString();
  const idSeed = url || `${item.title}-${dateISO}-${item.sourceName}`;

  return {
    id: createId(idSeed),
    title: item.title.trim(),
    url,
    dateISO,
    sourceName: item.sourceName,
    sourceType: item.sourceType,
    summary: summary.trim(),
    tags,
    severity,
    severityScore: score,
    cves
  };
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
    const paramsToDelete = [
      'utm_source',
      'utm_medium',
      'utm_campaign',
      'utm_term',
      'utm_content',
      'utm_id',
      'gclid',
      'fbclid',
      'mc_cid',
      'mc_eid',
      'ref',
      'ref_src'
    ];
    paramsToDelete.forEach(param => parsed.searchParams.delete(param));
    return parsed.toString();
  } catch (error) {
    return url.trim();
  }
}

function extractCves(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
  return Array.from(new Set(matches.map(match => match.toUpperCase())));
}

function extractTags(text, sourceType) {
  const lower = text.toLowerCase();
  const tags = new Set();

  if (sourceType === 'official') tags.add('advisory');
  if (sourceType === 'status') tags.add('incident');

  const tagMap = [
    { tag: 'ransomware', keywords: ['ransomware', 'extortion', 'ransom'] },
    { tag: 'breach', keywords: ['breach', 'leak', 'data exposure', 'stolen data'] },
    { tag: 'phishing', keywords: ['phishing', 'credential theft'] },
    { tag: 'malware', keywords: ['malware', 'trojan', 'botnet'] },
    { tag: 'vulnerability', keywords: ['vulnerability', 'cve', 'zero-day', 'zero day', 'rce', 'remote code'] },
    { tag: 'incident', keywords: ['outage', 'incident', 'disruption', 'degradation', 'service issue'] },
    { tag: 'advisory', keywords: ['advisory', 'alert', 'recommendation'] }
  ];

  tagMap.forEach(({ tag, keywords }) => {
    if (keywords.some(keyword => lower.includes(keyword))) {
      tags.add(tag);
    }
  });

  return Array.from(tags);
}

function scoreSeverity(text, sourceType) {
  const lower = text.toLowerCase();
  let score = 0;

  if (sourceType === 'official') score += 4;
  if (sourceType === 'news') score += 2;
  if (sourceType === 'status') score += 3;

  const rules = [
    { score: 5, keywords: ['critical', 'actively exploited', 'rce', 'remote code execution', 'zero-day', 'zero day'] },
    { score: 4, keywords: ['ransomware', 'breach', 'data leak', 'exfiltration', 'massive outage'] },
    { score: 3, keywords: ['high severity', 'privilege escalation', 'authentication bypass'] },
    { score: 2, keywords: ['medium', 'phishing', 'malware', 'ddos', 'service disruption', 'incident'] },
    { score: 1, keywords: ['advisory', 'alert', 'update', 'patch'] }
  ];

  rules.forEach(rule => {
    if (rule.keywords.some(keyword => lower.includes(keyword))) {
      score += rule.score;
    }
  });

  let severity = 'LOW';
  if (score >= 12) severity = 'CRITICAL';
  else if (score >= 9) severity = 'HIGH';
  else if (score >= 6) severity = 'MEDIUM';

  return { severity, score };
}

function dedupeItems(items) {
  const byUrl = new Map();
  const withoutUrl = [];

  items.forEach(item => {
    if (item.url) {
      const existing = byUrl.get(item.url);
      if (!existing || item.severityScore > existing.severityScore) {
        byUrl.set(item.url, item);
      }
    } else {
      withoutUrl.push(item);
    }
  });

  const combined = [...byUrl.values(), ...withoutUrl];
  const deduped = [];

  combined.forEach(item => {
    const duplicateIndex = deduped.findIndex(existing =>
      existing.sourceName === item.sourceName &&
      isSameDay(existing.dateISO, item.dateISO) &&
      titleSimilarity(existing.title, item.title) >= 0.8
    );
    if (duplicateIndex >= 0) {
      if (item.severityScore > deduped[duplicateIndex].severityScore) {
        deduped[duplicateIndex] = item;
      }
      return;
    }
    deduped.push(item);
  });

  return deduped;
}

function clusterItems(items) {
  const sorted = [...items].sort((a, b) => new Date(b.dateISO || 0) - new Date(a.dateISO || 0));
  const clusters = [];

  sorted.forEach(item => {
    const cluster = clusters.find(group => isSameStory(group.primary, item));
    if (cluster) {
      cluster.items.push(item);
      if (item.severityScore > cluster.primary.severityScore) {
        cluster.primary = item;
      }
      return;
    }
    clusters.push({ primary: item, items: [item] });
  });

  return clusters.map(group => {
    if (group.items.length === 1) {
      return group.primary;
    }
    const [primary, ...rest] = orderClusterItems(group.primary, group.items);
    return {
      ...primary,
      clusterItems: rest.map(item => ({
        id: item.id,
        title: item.title,
        url: item.url,
        dateISO: item.dateISO,
        sourceName: item.sourceName,
        sourceType: item.sourceType
      }))
    };
  });
}

function orderClusterItems(primary, items) {
  const sorted = [...items].sort((a, b) => b.severityScore - a.severityScore);
  const orderedPrimary = sorted.find(item => item.id === primary.id) || sorted[0];
  const rest = sorted.filter(item => item.id !== orderedPrimary.id);
  return [orderedPrimary, ...rest];
}

function isSameStory(a, b) {
  if (!a || !b) return false;
  const sameCve = a.cves.length && b.cves.length && a.cves.some(cve => b.cves.includes(cve));
  const similarTitle = titleSimilarity(a.title, b.title) >= 0.55;
  const withinRange = withinDays(a.dateISO, b.dateISO, 3);
  return sameCve || (similarTitle && withinRange);
}

function isSameDay(a, b) {
  if (!a || !b) return false;
  return a.slice(0, 10) === b.slice(0, 10);
}

function withinDays(a, b, days) {
  if (!a || !b) return false;
  const diff = Math.abs(new Date(a) - new Date(b));
  return diff <= days * 24 * 60 * 60 * 1000;
}

function titleSimilarity(a, b) {
  const aTokens = tokenizeTitle(a);
  const bTokens = tokenizeTitle(b);
  if (!aTokens.length || !bTokens.length) return 0;
  const intersection = aTokens.filter(token => bTokens.includes(token));
  const union = new Set([...aTokens, ...bTokens]);
  return intersection.length / union.size;
}

function tokenizeTitle(title) {
  if (!title) return [];
  const stopWords = new Set(['the', 'a', 'an', 'and', 'or', 'for', 'with', 'to', 'of', 'in', 'on', 'at', 'by']);
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .split(/\s+/)
    .filter(token => token && !stopWords.has(token));
}

function createId(value) {
  let hash = 0;
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i);
    hash |= 0;
  }
  return `news-${Math.abs(hash)}`;
}

function stripInternalFields(item) {
  const { severityScore, ...rest } = item;
  return rest;
}
