export default async function handler(req, res) {
  const { ip } = req.body;
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }

  if (!apiKey) {
    return res.status(400).json({ error: 'AbuseIPDB API key not configured' });
  }

  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ip=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose=`,
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
      return res.status(response.status).json({ error: data.errors?.[0]?.detail || 'AbuseIPDB API error' });
    }
    
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to check IP', details: error.message });
  }
}
