export default async function handler(req, res) {
  const { url } = req.body;
  
  if (!url) {
    return res.status(400).json({ error: 'URL is required' });
  }

  try {
    const body = new URLSearchParams();
    body.append('url', url);

    const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method: 'POST',
      body: body.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const data = await response.json();
    
    if (!response.ok) {
      return res.status(response.status).json({ error: 'URLhaus API error' });
    }
    
    res.status(200).json(data);
  } catch (error) {
    res.status(500).json({ error: 'Failed to check URL', details: error.message });
  }
}

