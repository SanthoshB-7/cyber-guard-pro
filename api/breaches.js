const cacheTtlMs = 6 * 60 * 60 * 1000;
let breachCache = null;

export default async function handler(req, res) {
  const timestamp = new Date().toISOString();
  try {
    // Fetch from multiple breach sources for comprehensive data
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 8000);

    // Option 1: Fetch from Breach Directory (free, no key needed)
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

    // Format the data for your dashboard
    const formattedBreaches = (Array.isArray(breachList) ? breachList : []).map(breach => normalizeBreach(breach));
    const sortedBreaches = sortBreachesByDate(formattedBreaches).slice(0, 50);

    breachCache = {
      breaches: sortedBreaches,
      timestamp,
      cachedAt: Date.now()
    };

    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      breaches: sortedBreaches, // Latest 50 breaches
      timestamp
    });
  } catch (error) {
    const allowFallback = req.query?.allowFallback === '1';
    console.error('Breach API Error:', error);

    res.setHeader('Content-Type', 'application/json');

    if (breachCache && Date.now() - breachCache.cachedAt <= cacheTtlMs) {
      res.status(200).json({
        breaches: breachCache.breaches,
        timestamp,
        stale: true
      });
      return;
    }

    if (allowFallback) {
      res.status(502).json({
        breaches: sortBreachesByDate(fallbackBreaches.map(breach => normalizeBreach(breach))).slice(0, 50),
        timestamp,
        fallback: true,
        error: error.message
      });
      return;
    }

    res.status(502).json({
      error: error.message,
      timestamp,
      fallback: false
    });
  }
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
    source: breach.source || 'Breach Directory'
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
