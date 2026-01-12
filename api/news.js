const feeds = [
  { source: 'CISA', url: 'https://www.cisa.gov/news-events/cybersecurity-advisories.xml', badgeColor: 'pink', category: 'Advisory' },
  { source: 'US-CERT', url: 'https://www.cisa.gov/news-events/alerts.xml', badgeColor: 'orange', category: 'Alert' },
  { source: 'NIST', url: 'https://www.nist.gov/news-events/cybersecurity/rss.xml', badgeColor: 'blue', category: 'Framework' }
];

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    const responses = await Promise.all(
      feeds.map(async (feed) => {
        const response = await fetch(feed.url);
        if (!response.ok) {
          return [];
        }
        const xmlText = await response.text();
        return parseFeed(xmlText, feed);
      })
    );

    const items = responses.flat().filter(item => item.link && item.link !== '#');
    res.status(200).json({ items });
  } catch (error) {
    res.status(500).json({ error: 'News API failed', details: error.message });
  }
}

function parseFeed(xmlText, feed) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  while ((match = itemRegex.exec(xmlText)) !== null) {
    const itemBlock = match[1];
    const title = getTagValue(itemBlock, 'title') || 'Security Update';
    const link = getTagValue(itemBlock, 'link') || '#';
    const pubDate = getTagValue(itemBlock, 'pubDate');
    const descriptionRaw = getTagValue(itemBlock, 'description') || '';
    const description = descriptionRaw.replace(/<[^>]*>/g, '').trim().slice(0, 140);
    const date = pubDate
      ? new Date(pubDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
      : 'Recent';

    items.push({
      category: feed.category,
      title,
      description,
      date,
      source: feed.source,
      badgeColor: feed.badgeColor,
      link
    });

    if (items.length >= 5) {
      break;
    }
  }
  return items;
}

function getTagValue(block, tag) {
  const regex = new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, 'i');
  const match = regex.exec(block);
  if (!match) {
    return '';
  }
  return match[1].replace(/<!\\[CDATA\\[|\\]\\]>/g, '').trim();
}
