export default async function handler(req, res) {
  try {
    const response = await fetch('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    
    if (!response.ok) {
      throw new Error(`CISA API error: ${response.status}`);
    }
    
    const data = await response.json();
    
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json(data);
  } catch (error) {
    console.error('CISA API Error:', error);
    res.status(500).json({ error: error.message });
  }
}
