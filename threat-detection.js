// ═══════════════════════════════════════════════════════════════════════════════
// THREAT DETECTION API STACK
// Checks URLs against multiple security databases
// ═══════════════════════════════════════════════════════════════════════════════

const fetch = require('node-fetch');

// API Keys (set in .env)
const API_KEYS = {
  VIRUSTOTAL: process.env.VIRUSTOTAL_API_KEY,
  URLSCAN: process.env.URLSCAN_API_KEY,
  GOOGLE_SAFE_BROWSING: process.env.GOOGLE_SAFE_BROWSING_KEY,
  IPQUALITYSCORE: process.env.IPQUALITYSCORE_API_KEY,
  ABUSEIPDB: process.env.ABUSEIPDB_API_KEY,
  PHISHTANK: process.env.PHISHTANK_API_KEY
};

// Known malicious patterns
const SUSPICIOUS_PATTERNS = [
  // Payloader domains
  /discord\.gift/i,
  /discordgift/i,
  /discord-nitro/i,
  /free-nitro/i,
  /steamcommunity\.[^c]/i,  // Fake Steam
  /steampowered\.[^c]/i,
  /discordapp\.[^c]/i,      // Fake Discord
  
  // URL shorteners (often used for malware)
  /bit\.ly/i,
  /tinyurl/i,
  /t\.co/i,
  /goo\.gl/i,
  /ow\.ly/i,
  /is\.gd/i,
  /buff\.ly/i,
  /adf\.ly/i,
  /shorte\.st/i,
  
  // Suspicious TLDs
  /\.(tk|ml|ga|cf|gq|xyz|top|work|click|link|club|online|site|website|space|pw|cc|ws)$/i,
  
  // IP-based URLs
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
  
  // Common phishing patterns
  /login.*verify/i,
  /verify.*account/i,
  /secure.*update/i,
  /account.*suspend/i,
  /paypal.*verify/i,
  /bank.*secure/i,
  
  // Executable downloads
  /\.(exe|msi|bat|cmd|ps1|vbs|scr|jar|apk)(\?|$)/i,
  
  // Grabber/stealer keywords
  /grabber/i,
  /stealer/i,
  /logger/i,
  /rat\b/i,
  /keylog/i
];

// Known safe domains (whitelist)
const SAFE_DOMAINS = [
  'discord.com',
  'discord.gg',
  'discordapp.com',
  'cdn.discordapp.com',
  'media.discordapp.net',
  'youtube.com',
  'youtu.be',
  'twitter.com',
  'x.com',
  'twitch.tv',
  'github.com',
  'reddit.com',
  'imgur.com',
  'giphy.com',
  'tenor.com',
  'google.com',
  'microsoft.com',
  'apple.com',
  'amazon.com',
  'wikipedia.org',
  'steam.com',
  'steampowered.com',
  'steamcommunity.com',
  'epicgames.com',
  'rockstargames.com',
  'spotify.com',
  'netflix.com'
];

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN SCAN FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

async function scanUrl(url) {
  const results = {
    url: url,
    safe: true,
    riskScore: 0,
    threats: [],
    checks: {},
    scannedAt: new Date().toISOString()
  };
  
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 1. WHITELIST CHECK
    // ═══════════════════════════════════════════════════════════════════════════
    if (SAFE_DOMAINS.some(safe => domain === safe || domain.endsWith('.' + safe))) {
      results.checks.whitelist = { safe: true, message: 'Known safe domain' };
      return results;
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 2. PATTERN MATCHING (Instant detection)
    // ═══════════════════════════════════════════════════════════════════════════
    for (const pattern of SUSPICIOUS_PATTERNS) {
      if (pattern.test(url)) {
        results.safe = false;
        results.riskScore += 40;
        results.threats.push({
          type: 'PATTERN_MATCH',
          severity: 'high',
          description: `URL matches suspicious pattern: ${pattern.toString()}`
        });
      }
    }
    results.checks.patterns = { 
      checked: true, 
      matches: results.threats.filter(t => t.type === 'PATTERN_MATCH').length 
    };
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 3. GOOGLE SAFE BROWSING
    // ═══════════════════════════════════════════════════════════════════════════
    if (API_KEYS.GOOGLE_SAFE_BROWSING) {
      try {
        const gsb = await checkGoogleSafeBrowsing(url);
        results.checks.googleSafeBrowsing = gsb;
        if (!gsb.safe) {
          results.safe = false;
          results.riskScore += 50;
          results.threats.push({
            type: 'GOOGLE_SAFE_BROWSING',
            severity: 'critical',
            description: `Google flagged: ${gsb.threatTypes?.join(', ') || 'Malicious'}`
          });
        }
      } catch (e) {
        results.checks.googleSafeBrowsing = { error: e.message };
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 4. VIRUSTOTAL
    // ═══════════════════════════════════════════════════════════════════════════
    if (API_KEYS.VIRUSTOTAL) {
      try {
        const vt = await checkVirusTotal(url);
        results.checks.virusTotal = vt;
        if (!vt.safe) {
          results.safe = false;
          results.riskScore += vt.positives * 5;
          results.threats.push({
            type: 'VIRUSTOTAL',
            severity: vt.positives > 5 ? 'critical' : 'high',
            description: `${vt.positives}/${vt.total} engines flagged this URL`
          });
        }
      } catch (e) {
        results.checks.virusTotal = { error: e.message };
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 5. URLSCAN.IO
    // ═══════════════════════════════════════════════════════════════════════════
    if (API_KEYS.URLSCAN) {
      try {
        const urlscan = await checkUrlScan(url);
        results.checks.urlscan = urlscan;
        if (!urlscan.safe) {
          results.safe = false;
          results.riskScore += 30;
          results.threats.push({
            type: 'URLSCAN',
            severity: 'high',
            description: urlscan.verdict || 'Flagged as malicious'
          });
        }
      } catch (e) {
        results.checks.urlscan = { error: e.message };
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 6. IPQUALITYSCORE (Domain reputation)
    // ═══════════════════════════════════════════════════════════════════════════
    if (API_KEYS.IPQUALITYSCORE) {
      try {
        const ipqs = await checkIPQualityScore(url);
        results.checks.ipQualityScore = ipqs;
        if (!ipqs.safe) {
          results.safe = false;
          results.riskScore += ipqs.riskScore || 25;
          results.threats.push({
            type: 'IPQUALITYSCORE',
            severity: ipqs.riskScore > 75 ? 'critical' : 'medium',
            description: `Risk score: ${ipqs.riskScore}% - ${ipqs.message || 'Suspicious'}`
          });
        }
      } catch (e) {
        results.checks.ipQualityScore = { error: e.message };
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 7. PHISHTANK
    // ═══════════════════════════════════════════════════════════════════════════
    if (API_KEYS.PHISHTANK) {
      try {
        const pt = await checkPhishTank(url);
        results.checks.phishTank = pt;
        if (!pt.safe) {
          results.safe = false;
          results.riskScore += 60;
          results.threats.push({
            type: 'PHISHTANK',
            severity: 'critical',
            description: 'Known phishing site'
          });
        }
      } catch (e) {
        results.checks.phishTank = { error: e.message };
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // 8. DOMAIN AGE CHECK
    // ═══════════════════════════════════════════════════════════════════════════
    try {
      const domainAge = await checkDomainAge(domain);
      results.checks.domainAge = domainAge;
      if (domainAge.daysOld < 30) {
        results.riskScore += 20;
        results.threats.push({
          type: 'NEW_DOMAIN',
          severity: 'medium',
          description: `Domain is only ${domainAge.daysOld} days old`
        });
      }
    } catch (e) {
      results.checks.domainAge = { error: e.message };
    }
    
    // Cap risk score at 100
    results.riskScore = Math.min(100, results.riskScore);
    
    // Determine final safety
    if (results.riskScore >= 50) {
      results.safe = false;
    }
    
  } catch (e) {
    results.error = e.message;
  }
  
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// API IMPLEMENTATIONS
// ═══════════════════════════════════════════════════════════════════════════════

// Google Safe Browsing
async function checkGoogleSafeBrowsing(url) {
  const response = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.GOOGLE_SAFE_BROWSING}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'unpatchedverify', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    }
  );
  
  const data = await response.json();
  
  if (data.matches && data.matches.length > 0) {
    return {
      safe: false,
      threatTypes: data.matches.map(m => m.threatType),
      matches: data.matches
    };
  }
  
  return { safe: true };
}

// VirusTotal
async function checkVirusTotal(url) {
  // First, submit URL for scanning
  const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
  
  const response = await fetch(
    `https://www.virustotal.com/api/v3/urls/${urlId}`,
    {
      headers: { 'x-apikey': API_KEYS.VIRUSTOTAL }
    }
  );
  
  if (response.status === 404) {
    // URL not in database, submit it
    const submitRes = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': API_KEYS.VIRUSTOTAL,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });
    return { safe: true, message: 'Submitted for scanning' };
  }
  
  const data = await response.json();
  
  if (data.data?.attributes?.last_analysis_stats) {
    const stats = data.data.attributes.last_analysis_stats;
    const positives = stats.malicious + stats.suspicious;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);
    
    return {
      safe: positives === 0,
      positives,
      total,
      stats
    };
  }
  
  return { safe: true };
}

// URLScan.io
async function checkUrlScan(url) {
  // Search for existing scan
  const searchRes = await fetch(
    `https://urlscan.io/api/v1/search/?q=page.url:"${encodeURIComponent(url)}"`,
    {
      headers: { 'API-Key': API_KEYS.URLSCAN }
    }
  );
  
  const searchData = await searchRes.json();
  
  if (searchData.results && searchData.results.length > 0) {
    const latest = searchData.results[0];
    return {
      safe: !latest.verdicts?.malicious,
      verdict: latest.verdicts?.overall?.verdict,
      score: latest.verdicts?.overall?.score,
      screenshot: latest.screenshot
    };
  }
  
  // Submit new scan
  const submitRes = await fetch('https://urlscan.io/api/v1/scan/', {
    method: 'POST',
    headers: {
      'API-Key': API_KEYS.URLSCAN,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ url, visibility: 'unlisted' })
  });
  
  return { safe: true, message: 'Submitted for scanning' };
}

// IPQualityScore
async function checkIPQualityScore(url) {
  const response = await fetch(
    `https://ipqualityscore.com/api/json/url/${API_KEYS.IPQUALITYSCORE}/${encodeURIComponent(url)}`
  );
  
  const data = await response.json();
  
  return {
    safe: !data.unsafe && !data.phishing && !data.malware,
    riskScore: data.risk_score || 0,
    phishing: data.phishing,
    malware: data.malware,
    suspicious: data.suspicious,
    message: data.message,
    domain_age: data.domain_age
  };
}

// PhishTank
async function checkPhishTank(url) {
  const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `url=${encodeURIComponent(url)}&format=json&app_key=${API_KEYS.PHISHTANK}`
  });
  
  const data = await response.json();
  
  return {
    safe: !data.results?.in_database || !data.results?.valid,
    inDatabase: data.results?.in_database,
    verified: data.results?.verified
  };
}

// Domain Age (using WHOIS API)
async function checkDomainAge(domain) {
  // Simple check using a free API
  try {
    const response = await fetch(`https://api.api-ninjas.com/v1/whois?domain=${domain}`, {
      headers: { 'X-Api-Key': process.env.API_NINJAS_KEY || '' }
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.creation_date) {
        const created = new Date(data.creation_date);
        const daysOld = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
        return { daysOld, createdAt: data.creation_date };
      }
    }
  } catch (e) {}
  
  return { daysOld: -1, error: 'Could not determine' };
}

// ═══════════════════════════════════════════════════════════════════════════════
// IP THREAT CHECK
// ═══════════════════════════════════════════════════════════════════════════════

async function checkIP(ip) {
  const results = {
    ip,
    safe: true,
    riskScore: 0,
    threats: [],
    checks: {}
  };
  
  // AbuseIPDB
  if (API_KEYS.ABUSEIPDB) {
    try {
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`,
        {
          headers: {
            'Key': API_KEYS.ABUSEIPDB,
            'Accept': 'application/json'
          }
        }
      );
      
      const data = await response.json();
      
      if (data.data) {
        results.checks.abuseIPDB = {
          abuseScore: data.data.abuseConfidenceScore,
          totalReports: data.data.totalReports,
          isPublic: data.data.isPublic,
          isTor: data.data.isTor,
          countryCode: data.data.countryCode
        };
        
        if (data.data.abuseConfidenceScore > 25) {
          results.safe = false;
          results.riskScore += data.data.abuseConfidenceScore;
          results.threats.push({
            type: 'ABUSEIPDB',
            severity: data.data.abuseConfidenceScore > 75 ? 'critical' : 'high',
            description: `Abuse score: ${data.data.abuseConfidenceScore}%, ${data.data.totalReports} reports`
          });
        }
        
        if (data.data.isTor) {
          results.threats.push({
            type: 'TOR_EXIT',
            severity: 'high',
            description: 'Tor exit node detected'
          });
          results.riskScore += 30;
        }
      }
    } catch (e) {
      results.checks.abuseIPDB = { error: e.message };
    }
  }
  
  // IPQualityScore IP check
  if (API_KEYS.IPQUALITYSCORE) {
    try {
      const response = await fetch(
        `https://ipqualityscore.com/api/json/ip/${API_KEYS.IPQUALITYSCORE}/${ip}`
      );
      
      const data = await response.json();
      
      results.checks.ipqs = {
        fraudScore: data.fraud_score,
        vpn: data.vpn,
        tor: data.tor,
        proxy: data.proxy,
        bot: data.bot_status,
        country: data.country_code
      };
      
      if (data.fraud_score > 75 || data.vpn || data.tor || data.proxy) {
        results.safe = false;
        results.riskScore += data.fraud_score || 30;
        
        if (data.vpn) results.threats.push({ type: 'VPN', severity: 'medium', description: 'VPN detected' });
        if (data.tor) results.threats.push({ type: 'TOR', severity: 'high', description: 'Tor network detected' });
        if (data.proxy) results.threats.push({ type: 'PROXY', severity: 'medium', description: 'Proxy detected' });
        if (data.bot_status) results.threats.push({ type: 'BOT', severity: 'high', description: 'Bot-like behavior' });
      }
    } catch (e) {
      results.checks.ipqs = { error: e.message };
    }
  }
  
  results.riskScore = Math.min(100, results.riskScore);
  return results;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BULK SCAN (for Discord messages with multiple links)
// ═══════════════════════════════════════════════════════════════════════════════

async function scanMessage(content) {
  // Extract URLs from message
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
  const urls = content.match(urlRegex) || [];
  
  if (urls.length === 0) {
    return { safe: true, urls: [], threats: [] };
  }
  
  const results = {
    safe: true,
    urls: [],
    threats: [],
    totalRisk: 0
  };
  
  for (const url of urls.slice(0, 5)) { // Limit to 5 URLs
    const scan = await scanUrl(url);
    results.urls.push(scan);
    
    if (!scan.safe) {
      results.safe = false;
      results.threats.push(...scan.threats);
      results.totalRisk = Math.max(results.totalRisk, scan.riskScore);
    }
  }
  
  return results;
}

module.exports = {
  scanUrl,
  scanMessage,
  checkIP,
  SUSPICIOUS_PATTERNS,
  SAFE_DOMAINS
};
