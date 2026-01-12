export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.NVD_API_KEY;
  const query = req.query?.query;

  if (!query || !query.trim()) {
    return res.status(400).json({ error: 'Query is required' });
  }

  const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(query.trim())}`;

  try {
    const response = await fetch(nvdUrl, {
      headers: apiKey ? { apiKey } : undefined
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: data?.message || 'NVD API failed'
      });
    }

    res.status(200).json({
      success: true,
      vulnerabilities: data?.vulnerabilities || []
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
}
