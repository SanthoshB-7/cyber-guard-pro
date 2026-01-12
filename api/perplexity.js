export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const apiKey = process.env.PERPLEXITY_API_KEY;
  const query = req.body?.query;

  if (!apiKey) {
    return res.status(400).json({ error: 'API key not configured' });
  }

  if (!query || !query.trim()) {
    return res.status(400).json({ error: 'Query is required' });
  }

  try {
    const response = await fetch('https://api.perplexity.ai/chat/completions', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'sonar-pro',
        messages: [
          {
            role: 'user',
            content: query.trim()
          }
        ],
        max_tokens: 1000,
        temperature: 0.7
      })
    });

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        error: data?.error?.message || 'Perplexity API failed'
      });
    }

    const content = data?.choices?.[0]?.message?.content;
    if (!content) {
      return res.status(500).json({ error: 'Empty response from Perplexity' });
    }

    res.status(200).json({
      success: true,
      content
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error', details: error.message });
  }
}
