const CACHE_TTL_MS = 30 * 60 * 1000;
const CACHE_HEADER = 's-maxage=1800, stale-while-revalidate=600';
const FORCE_REFRESH_MIN_MS = 5 * 60 * 1000;
const MAX_ITEMS = 50;

const feeds = [
  {
    vendor: 'Microsoft',
    url: 'https://api.msrc.microsoft.com/update-guide/rss'
  },
  {
    vendor: 'Cisco',
    url: 'https://tools.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml'
  },
  {
    vendor: 'Fortinet',
    url: 'https://www.fortiguard.com/rss/psirt/fg-psirt.xml'
  },
  {
    vendor: 'Palo Alto Networks',
    url: 'https://security.paloaltonetworks.com/rss'
  },
  {
    vendor: 'VMware',
    url: 'https://www.vmware.com/security/advisories.xml'
  }
];

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

  try {
    const results = await Promise.all(
      feeds.map(async (feed) => {
        const xmlText = await fetchFeed(feed.url);
        if (!xmlText) return [];
        return parseFeed(xmlText, feed.vendor);
      })
    );

    const items = dedupeItems(results.flat())
      .filter(Boolean)
      .sort((a, b) => new Date(b.publishedISO || 0) - new Date(a.publishedISO || 0))
      .slice(0, MAX_ITEMS);

    const payload = {
      items,
      timestamp: new Date().toISOString(),
      sourceCount: feeds.length
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
    return res.status(500).json({ error: 'Advisories API failed', details: error.message });
  }
}

async function fetchFeed(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) return null;
    return await response.text();
  } catch (error) {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function parseFeed(xmlText, vendor) {
  const items = [];
  const rssItems = extractBlocks(xmlText, 'item');
  const atomEntries = extractBlocks(xmlText, 'entry');
  const blocks = rssItems.length ? rssItems : atomEntries;

  blocks.forEach((block) => {
    const title = decodeEntities(getTagValue(block, 'title')) || 'Security advisory';
    const link = getLink(block) || getTagValue(block, 'guid') || '';
    const pubDate = getTagValue(block, 'pubDate') || getTagValue(block, 'published') || getTagValue(block, 'updated') || getTagValue(block, 'dc:date');
    const descriptionRaw = getTagValue(block, 'description') || getTagValue(block, 'summary') || getTagValue(block, 'content:encoded') || '';
    const summary = stripHtml(descriptionRaw).slice(0, 280);
    const publishedISO = normalizeDate(pubDate) || new Date().toISOString();
    const cves = extractCves(`${title} ${summary}`);
    const idSeed = `${vendor}-${link || title}-${publishedISO}`;

    items.push({
      id: createId(idSeed),
      title: title.trim(),
      url: link,
      publishedISO,
      vendor,
      summary,
      cves
    });
  });

  return items;
}

function extractBlocks(xmlText, tag) {
  const regex = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'gi');
  const blocks = [];
  let match;
  while ((match = regex.exec(xmlText)) !== null) {
    blocks.push(match[1]);
  }
  return blocks;
}

function getTagValue(block, tag) {
  const regex = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = regex.exec(block);
  if (!match) return '';
  return match[1].replace(/<!\\[CDATA\\[|\\]\]>/g, '').trim();
}

function getLink(block) {
  const hrefMatch = block.match(/<link[^>]*href=["']([^"']+)["'][^>]*>/i);
  if (hrefMatch) return hrefMatch[1].trim();
  const tagLink = getTagValue(block, 'link');
  return tagLink ? tagLink.trim() : '';
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

function extractCves(text) {
  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
  return Array.from(new Set(matches.map(value => value.toUpperCase())));
}

function dedupeItems(items) {
  const seen = new Set();
  return items.filter((item) => {
    const key = (item.url || item.title || '').toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function createId(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i += 1) {
    hash = (hash << 5) - hash + input.charCodeAt(i);
    hash |= 0;
  }
  return `adv-${Math.abs(hash)}`;
}

function decodeEntities(value) {
  return value
    .replace(/&amp;/g, '&')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>');
}
