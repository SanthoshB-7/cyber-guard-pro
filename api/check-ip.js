export default async function handler(req, res) {
  // Allow CORS
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  let ip = req.body?.ip || req.body?.toString();

  if (!apiKey) {
    return res.status(400).json({ error: 'API key not configured' });
  }

  if (!ip || !ip.trim()) {
    return res.status(400).json({ error: 'IP address is required' });
  }

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        method: 'GET',
        headers: {
          'Key': apiKey,
          'Accept': 'application/json'
        }
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: data?.errors?.[0]?.detail || 'AbuseIPDB API failed'
      });
    }

    const ipData = data?.data || {};
    res.status(200).json({
      success: true,
      ip: ipData.ipAddress || ip.trim(),
      abuseScore: ipData.abuseConfidenceScore || 0,
      totalReports: ipData.totalReports || 0,
      isp: ipData.isp || 'Unknown',
      domain: ipData.domain || 'None',
      usageType: ipData.usageType || 'Unknown',
      countryCode: ipData.countryCode || 'Unknown'
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
}
