export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.NVD_API_KEY;
  const days = Number(req.query?.days || 7);
  const severity = req.query?.severity || 'CRITICAL';

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(endDate.getDate() - (Number.isFinite(days) ? days : 7));

  const startIso = startDate.toISOString().split('T')[0];
  const endIso = endDate.toISOString().split('T')[0];

  const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${startIso}T00:00:00.000&pubEndDate=${endIso}T23:59:59.999&cvssV3Severity=${encodeURIComponent(severity)}`;

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
