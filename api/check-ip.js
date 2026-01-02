export default async function handler(req, res) {
  const { ip } = req.body;
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  // Debug: Log what we're seeing
  console.log('Available env vars:', Object.keys(process.env).filter(k => k.includes('ABUSE')));
  console.log('ABUSEIPDB_API_KEY value:', apiKey ? 'SET' : 'NOT SET');

  if (!ip) {
    return res.status(400).json({ error: 'IP address is required' });
  }

  if (!apiKey) {
    return res.status(400).json({ 
      error: 'AbuseIPDB API key not configured',
      debug: 'Check Vercel Environment Variables'
    });
  }

  try {
    const params = new URLSearchParams({
      ip: ip,
      maxAgeInDays: '90',
      verbose: ''
    });

    const response = await fetch('https://api.abuseipdb.com/api/v2/check?' + params.toString(), {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });

    const data = await response.json();
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to check IP', details: error.message });
  }
}

