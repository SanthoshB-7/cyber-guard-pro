export default async function handler(req, res) {
  try {
    // Fetch from multiple breach sources for comprehensive data
    
    // Option 1: Fetch from Breach Directory (free, no key needed)
    const breachResponse = await fetch('https://breachdirectory.org/api/v1/breach');
    
    if (!breachResponse.ok) {
      throw new Error('Breach API error');
    }
    
    const breachData = await breachResponse.json();
    
    // Format the data for your dashboard
    const formattedBreaches = breachData.map(breach => ({
      name: breach.name || breach.title,
      date: breach.date_discovered || breach.breach_date,
      recordsAffected: breach.records_affected || breach.num_records,
      dataExposed: breach.data_exposed || breach.compromised_data,
      description: breach.description || 'Data breach incident',
      severity: calculateSeverity(breach.records_affected || 0),
      source: 'Breach Directory'
    }));
    
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
