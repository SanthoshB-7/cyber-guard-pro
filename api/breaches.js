export default async function handler(req, res) {
  try {
    // Fetch from multiple breach sources for comprehensive data
    
    // Option 1: Fetch from Breach Directory (free, no key needed)
    const breachResponse = await fetch('https://breachdirectory.org/api/v1/breach');
    
    if (!breachResponse.ok) {
      throw new Error('Breach API error');
    }
    
    const breachData = await breachResponse.json();
    const breachList = Array.isArray(breachData)
      ? breachData
      : breachData?.data || breachData?.breaches || [];

    // Format the data for your dashboard
    const formattedBreaches = breachList.map(breach => {
      const recordsAffected =
        breach.records_affected ??
        breach.num_records ??
        breach.recordsAffected ??
        breach.records ??
        0;
      return {
        name: breach.name || breach.title || breach.company || 'Unknown',
        date:
          breach.date_discovered ||
          breach.breach_date ||
          breach.date ||
          breach.discovered ||
          new Date().toISOString().split('T')[0],
        recordsAffected,
        dataExposed: breach.data_exposed || breach.compromised_data || breach.data || '',
        description: breach.description || breach.summary || 'Data breach incident',
        severity: calculateSeverity(Number(recordsAffected) || 0),
        source: breach.source || 'Breach Directory'
      };
    });
    
    res.setHeader('Content-Type', 'application/json');
    res.status(200).json({
      breaches: formattedBreaches.slice(0, 50), // Latest 50 breaches
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('Breach API Error:', error);
    res.status(500).json({ error: error.message });
  }
}

function calculateSeverity(recordCount) {
  if (recordCount > 1000000) return 'CRITICAL';
  if (recordCount > 100000) return 'HIGH';
  if (recordCount > 10000) return 'MEDIUM';
  return 'LOW';
}
