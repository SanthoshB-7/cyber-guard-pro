export default async function handler(req, res) {
  // Allow CORS
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  let url = req.body?.url || req.body?.toString();

  if (!apiKey) {
    return res.status(400).json({ error: 'API key not configured' });
  }

  if (!url || !url.trim()) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const params = new URLSearchParams();
    params.append('url', url.trim());

    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      body: params.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'x-apikey': apiKey
      }
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({ error: data?.error?.message || 'VirusTotal API failed' });
    }

    const analysisId = data?.data?.id;
    if (!analysisId) {
      return res.status(500).json({ error: 'VirusTotal analysis ID missing' });
    }

    const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': apiKey
      }
    });

    const analysisData = await analysisResponse.json();
    if (!analysisResponse.ok) {
      return res.status(analysisResponse.status).json({
        error: analysisData?.error?.message || 'VirusTotal analysis failed'
      });
    }

    const stats = analysisData?.data?.attributes?.stats || {};
    res.status(200).json({
      success: true,
      analysisId,
      lastAnalysisStats: stats
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
}

