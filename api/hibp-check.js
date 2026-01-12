export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.HIBP_API_KEY;
  const email = req.body?.email;

  if (!apiKey) {
    return res.status(400).json({ error: 'API key not configured' });
  }

  if (!email || !email.trim()) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    const response = await fetch(
      `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email.trim())}`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'CyberSecCommand'
        }
      }
    );

    if (response.status === 404) {
      return res.status(404).json({ breaches: [] });
    }

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: data?.message || 'HIBP API failed'
      });
    }

    res.status(200).json({
      breaches: data || []
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
}
