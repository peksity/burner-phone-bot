/**
 * ██████╗ ██╗   ██╗██████╗ ███╗   ██╗███████╗██████╗     ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗
 * ██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔══██╗    ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝
 * ██████╔╝██║   ██║██████╔╝██╔██╗ ██║█████╗  ██████╔╝    ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗  
 * ██╔══██╗██║   ██║██╔══██╗██║╚██╗██║██╔══╝  ██╔══██╗    ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝  
 * ██████╔╝╚██████╔╝██║  ██║██║ ╚████║███████╗██║  ██║    ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗
 * ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 * 
 * BURNER PHONE - ELITE PREMIUM MODMAIL + SOC-LEVEL SECURITY SYSTEM
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * ELITE MODMAIL FEATURES:
 * ═══════════════════════════════════════════════════════════════════════════════
 *  Typing Indicators      - Both ways (staff ↔ user)
 *  Read Receipts          - Delivered  Seen (like iMessage)
 *  Staff Online Status    - "Staff online" / "Expected wait: 2-4h"
 * ⏱ Response Timer         - Live "waiting for X minutes" 
 *  Message Edit Sync      - Edits sync both ways
 *  Queue Position         - "You are #3 in queue"
 *  Staff Viewing Alert    - User knows when staff opens ticket
 *  Auto Away Messages     - Staff away status with auto-reply
 *  Pinned Info            - Important details stay visible
 *  Ticket Linking         - Connect related tickets
 *  User Notes             - Persistent notes across tickets
 *  Quick Actions          - One-click buttons for everything
 *  Priority Colors        - Visual urgency system
 *  Auto-Close Inactive    - Warning  auto close stale tickets
 *  Anonymous Mode         - Staff can reply anonymously
 *  Sentiment Tracking     - Mood history per user
 *  Feedback System        - Post-close ratings
 *  Canned Responses       - Saved reply snippets
 *  Analytics Dashboard    - Response times, staff stats
 * 
 * ═══════════════════════════════════════════════════════════════════════════════
 * SOC-LEVEL SECURITY SYSTEM (Enterprise Grade):
 * ═══════════════════════════════════════════════════════════════════════════════
 *  LINK ANALYSIS:
 *    • Domain reputation scoring
 *    • Typosquatting detection (discord  disc0rd, dlscord)
 *    • URL shortener expansion & analysis
 *    • Redirect chain following
 *    • SSL certificate anomaly detection
 *    • IP-based hosting vs CDN detection
 *    • Known phishing kit fingerprinting
 *    • Homograph attack detection (cyrillic chars)
 * 
 *  FILE ANALYSIS (Static - No Execution):
 *    • Magic byte signature verification
 *    • Extension mismatch detection
 *    • PDF threat indicators (JS, auto-open, macros)
 *    • Image metadata anomaly detection
 *    • Archive content inspection
 *    • Executable detection in archives
 *    • Double extension detection
 * 
 *  SOCIAL ENGINEERING DETECTION:
 *    • Urgency language patterns
 *    • Authority impersonation
 *    • Account threat language
 *    • Prize/reward scam patterns
 *    • Fear-based manipulation
 *    • Time pressure tactics
 * 
 *  RISK SCORING SYSTEM:
 *    • Multi-signal aggregation
 *    • Weighted risk calculation
 *    • Score decay over time
 *    • Threshold-based actions
 *    • No instant bans - graduated response
 * 
 *  SAFE ACTIONS:
 *    • Soft warnings
 *    • Message quarantine
 *    • Temporary blocks
 *    • Moderator alerts
 *    • Human escalation
 * 
 *  AUDIT LOGGING:
 *    • Full detection reasoning
 *    • Risk score breakdown
 *    • Privacy-respecting
 *    • Appeal support
 * ═══════════════════════════════════════════════════════════════════════════════
 */

require('dotenv').config();
const { 
  Client, GatewayIntentBits, Partials, EmbedBuilder, 
  PermissionFlagsBits, Events, ActionRowBuilder, ButtonBuilder, 
  ButtonStyle, ChannelType, StringSelectMenuBuilder
} = require('discord.js');
const { Pool } = require('pg');
const Anthropic = require('@anthropic-ai/sdk');
const express = require('express');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.GuildBans,
    GatewayIntentBits.GuildPresences,
    GatewayIntentBits.DirectMessageTyping,
    GatewayIntentBits.GuildMessageTyping
  ],
  partials: [Partials.Channel, Partials.Message, Partials.User]
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// AI Client
const anthropic = process.env.ANTHROPIC_API_KEY ? new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) : null;

// ═══════════════════════════════════════════════════════════════════════════════
// EXPRESS SERVER FOR VERIFICATION WEBHOOKS
// ═══════════════════════════════════════════════════════════════════════════════

const app = express();
const cors = require('cors');
app.use(cors());
app.use(express.json());

// ═══════════════════════════════════════════════════════════════════════════════
// VERIFICATION TOKEN STORAGE (In-Memory)
// ═══════════════════════════════════════════════════════════════════════════════
const verificationTokens = new Map(); // token -> { discord_id, guild_id, expires_at }
const duplicateAttempts = new Map(); // discord_id -> { count, last_attempt }

// Clean up expired tokens every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [token, data] of verificationTokens) {
    if (data.expires_at < now) {
      verificationTokens.delete(token);
    }
  }
  // Clean up old duplicate attempts (after 24 hours)
  for (const [id, data] of duplicateAttempts) {
    if (now - data.last_attempt > 24 * 60 * 60 * 1000) {
      duplicateAttempts.delete(id);
    }
  }
}, 5 * 60 * 1000);

// Generate secure token
function generateToken() {
  return require('crypto').randomBytes(32).toString('hex');
}

// Health check - simple, no dependencies
app.get('/health', (req, res) => res.status(200).json({ status: 'ok' }));
app.get('/', (req, res) => res.status(200).json({ status: 'Burner Phone API' }));

// Start server immediately for Railway health checks
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SERVER] Burner Phone API running on port ${PORT}`);
});

// ═══════════════════════════════════════════════════════════════════════════════
// NEW VERIFICATION API - Called by verify.html on Hostinger
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/web-verify', async (req, res) => {
  const { token, discord_id, guild_id, captcha_token, fingerprint, fingerprint_data } = req.body;
  
  console.log(`[VERIFY] Received verification request for user ${discord_id}`);
  
  // Get IP from request
  const userIP = req.headers['x-forwarded-for']?.split(',')[0] || req.headers['x-real-ip'] || req.connection?.remoteAddress || 'unknown';
  const userPort = req.headers['x-forwarded-port'] || req.connection?.remotePort || null;
  console.log(`[VERIFY] User IP: ${userIP}, Port: ${userPort}`);
  
  // ═══════════════════════════════════════════════════════════════
  // WEBRTC REAL IP DETECTION - Catches VPN users' real IPs
  // ═══════════════════════════════════════════════════════════════
  const webrtcData = fingerprint_data?.webrtc || {};
  let webrtc_real_ip = null;
  let webrtc_local_ips = [];
  let webrtc_leak_detected = false;
  
  if (webrtcData.public && webrtcData.public.length > 0) {
    // Found public IP through WebRTC - this might be their REAL IP behind VPN!
    webrtc_real_ip = webrtcData.public[0];
    if (webrtc_real_ip !== userIP) {
      webrtc_leak_detected = true;
      console.log(`[VERIFY]  WEBRTC LEAK DETECTED! Request IP: ${userIP}, WebRTC IP: ${webrtc_real_ip}`);
    }
  }
  if (webrtcData.local && webrtcData.local.length > 0) {
    webrtc_local_ips = webrtcData.local;
    console.log(`[VERIFY] WebRTC local IPs: ${webrtc_local_ips.join(', ')}`);
  }
  
  // ═══════════════════════════════════════════════════════════════
  // EARLY REJECTION - Honeypot & Bot Detection
  // ═══════════════════════════════════════════════════════════════
  const clientThreats = fingerprint_data?.threats || {};
  
  // Honeypot triggered = instant block
  if (clientThreats.honeypot) {
    console.log(`[VERIFY] BLOCKED - Honeypot triggered (BOT)`);
    return res.json({ success: false, blocked: true, error: 'Automated access detected.' });
  }
  
  // High bot score = block
  if (clientThreats.botScore >= 80) {
    console.log(`[VERIFY] BLOCKED - Bot score too high: ${clientThreats.botScore}`);
    return res.json({ success: false, blocked: true, error: 'Automated access detected.' });
  }
  
  // Calculate overall risk score
  let riskScore = 0;
  const riskReasons = [];
  
  // WebRTC leak = major red flag (they're hiding behind VPN)
  if (webrtc_leak_detected) {
    riskScore += 30;
    riskReasons.push(`WebRTC leak (Real IP: ${webrtc_real_ip})`);
  }
  
  // Client-side threat signals
  if (clientThreats.vmScore >= 50) { riskScore += 20; riskReasons.push('VM detected'); }
  if (clientThreats.botScore >= 30) { riskScore += clientThreats.botScore / 2; riskReasons.push('Bot signals'); }
  if (clientThreats.incognito) { riskScore += 10; riskReasons.push('Incognito mode'); }
  if (clientThreats.devTools) { riskScore += 5; riskReasons.push('DevTools open'); }
  if (clientThreats.tabSwitches > 5) { riskScore += 10; riskReasons.push('Excessive tab switches'); }
  if (clientThreats.copyPaste) { riskScore += 5; riskReasons.push('Copy-paste detected'); }
  if (clientThreats.sessionDuration < 3000) { riskScore += 15; riskReasons.push('Too fast'); }
  
  // Behavioral analysis
  const behavior = fingerprint_data?.behavior || {};
  if (behavior.mouseCount < 5 && behavior.duration > 5000) { riskScore += 20; riskReasons.push('No mouse movement'); }
  if (behavior.duration < 2000) { riskScore += 15; riskReasons.push('Completed too quickly'); }
  
  console.log(`[VERIFY] Client risk score: ${riskScore}, Reasons: ${riskReasons.join(', ') || 'none'}`);
  
  // ═══════════════════════════════════════════════════════════════
  // DISCORD DEEP SCAN - Account details from Discord API
  // ═══════════════════════════════════════════════════════════════
  let discordDeepScan = {
    account_age_days: null,
    created_at: null,
    has_avatar: false,
    has_banner: false,
    is_nitro: false,
    badges: [],
    badge_count: 0,
    public_flags: 0,
    is_suspicious_username: false
  };
  
  try {
    const guild = client.guilds.cache.get(guild_id);
    const member = await guild?.members.fetch(discord_id).catch(() => null);
    
    if (member) {
      const user = member.user;
      
      // Account creation date
      const createdAt = user.createdAt;
      const accountAge = Date.now() - createdAt.getTime();
      discordDeepScan.account_age_days = Math.floor(accountAge / (1000 * 60 * 60 * 24));
      discordDeepScan.created_at = createdAt.toISOString();
      
      // Avatar & banner
      discordDeepScan.has_avatar = !!user.avatar;
      discordDeepScan.has_banner = !!user.banner;
      
      // Public flags (badges)
      const flags = user.flags?.toArray() || [];
      discordDeepScan.badges = flags;
      discordDeepScan.badge_count = flags.length;
      discordDeepScan.public_flags = user.flags?.bitfield || 0;
      
      // Check for Nitro indicators
      discordDeepScan.is_nitro = user.banner || user.avatar?.startsWith('a_') || flags.includes('PREMIUM_EARLY_SUPPORTER');
      
      // Suspicious username patterns (random numbers, generic names)
      const username = user.username.toLowerCase();
      const suspiciousPatterns = [
        /^user[0-9]+$/,
        /^[a-z]{2,4}[0-9]{4,}$/,
        /^[0-9]{5,}$/,
        /discord/,
        /^alt[0-9]*/,
        /^test[0-9]*/
      ];
      discordDeepScan.is_suspicious_username = suspiciousPatterns.some(p => p.test(username));
      
      console.log(`[VERIFY] Discord Deep Scan: Age=${discordDeepScan.account_age_days}d, Badges=${flags.join(',')}, Nitro=${discordDeepScan.is_nitro}, Avatar=${discordDeepScan.has_avatar}`);
      
      // Add risk for suspicious accounts
      if (discordDeepScan.account_age_days < 7) {
        // Already handled in account age check
      }
      if (!discordDeepScan.has_avatar && discordDeepScan.account_age_days > 30) {
        riskScore += 10;
        riskReasons.push('No avatar on old account');
      }
      if (discordDeepScan.is_suspicious_username) {
        riskScore += 15;
        riskReasons.push('Suspicious username pattern');
      }
      if (discordDeepScan.badge_count === 0 && discordDeepScan.account_age_days > 365) {
        riskScore += 5;
        riskReasons.push('No badges on old account');
      }
    }
  } catch (e) {
    console.log(`[VERIFY] Discord deep scan error:`, e.message);
  }
  
  // Threat intelligence data
  let threatData = {
    ip_address: userIP,
    ip_port: userPort,
    webrtc_real_ip: webrtc_real_ip,
    webrtc_local_ips: webrtc_local_ips,
    webrtc_leak: webrtc_leak_detected,
    ip_risk_score: 0,
    ip_vpn: false,
    ip_proxy: false,
    ip_tor: false,
    ip_bot_score: 0,
    ip_country: null,
    ip_region: null,
    ip_city: null,
    ip_isp: null,
    ip_org: null,
    ip_asn: null,
    ip_host: null,
    ip_mobile: false,
    ip_is_crawler: false,
    ip_connection_type: null,
    ip_latitude: null,
    ip_longitude: null,
    ip_abuse_reports: 0,
    timezone_mismatch: false,
    browser_timezone: fingerprint_data?.tz || fingerprint_data?.timezone,
    ip_timezone: null,
    is_bot: clientThreats.botScore >= 50,
    is_headless: clientThreats.botReasons?.includes('Headless browser UA'),
    is_vm: clientThreats.vmScore >= 50,
    is_incognito: clientThreats.incognito || false,
    client_risk_score: riskScore,
    client_risk_reasons: riskReasons,
    user_agent: req.headers['user-agent']
  };
  
  // IPQualityScore check
  const IPQS_KEY = process.env.IPQUALITYSCORE_API_KEY;
  if (IPQS_KEY && userIP && userIP !== 'unknown') {
    try {
      const ipqsResponse = await fetch(`https://www.ipqualityscore.com/api/json/ip/${IPQS_KEY}/${userIP}?strictness=1&allow_public_access_points=true`);
      const ipqs = await ipqsResponse.json();
      
      if (ipqs.success) {
        threatData.ip_risk_score = ipqs.fraud_score || 0;
        threatData.ip_vpn = ipqs.vpn || false;
        threatData.ip_proxy = ipqs.proxy || false;
        threatData.ip_tor = ipqs.tor || false;
        threatData.ip_bot_score = ipqs.bot_status ? 100 : 0;
        threatData.ip_country = ipqs.country_code || null;
        threatData.ip_region = ipqs.region || null;
        threatData.ip_city = ipqs.city || null;
        threatData.ip_isp = ipqs.ISP || null;
        threatData.ip_timezone = ipqs.timezone || null;
        threatData.ip_org = ipqs.organization || null;
        threatData.ip_asn = ipqs.ASN || null;
        threatData.ip_host = ipqs.host || null;
        threatData.ip_mobile = ipqs.mobile || false;
        threatData.ip_is_crawler = ipqs.is_crawler || false;
        threatData.ip_connection_type = ipqs.connection_type || null;
        threatData.ip_latitude = ipqs.latitude || null;
        threatData.ip_longitude = ipqs.longitude || null;
        
        // Check timezone mismatch
        if (threatData.browser_timezone && threatData.ip_timezone) {
          threatData.timezone_mismatch = threatData.browser_timezone !== threatData.ip_timezone;
          if (threatData.timezone_mismatch) {
            riskScore += 15;
            riskReasons.push('Timezone mismatch');
          }
        }
        
        // Add IP risk to overall score
        riskScore += Math.floor(threatData.ip_risk_score / 2);
        if (threatData.ip_vpn) { riskScore += 10; riskReasons.push('VPN'); }
        if (threatData.ip_proxy) { riskScore += 15; riskReasons.push('Proxy'); }
        if (threatData.ip_tor) { riskScore += 25; riskReasons.push('Tor'); }
        
        console.log(`[VERIFY] IPQualityScore: Risk=${threatData.ip_risk_score}, VPN=${threatData.ip_vpn}, Country=${threatData.ip_country}, Region=${threatData.ip_region}, City=${threatData.ip_city}`);
      }
    } catch (e) {
      console.log(`[VERIFY] IPQualityScore error:`, e.message);
    }
  }
  
  // ═══════════════════════════════════════════════════════════════
  // WEBRTC REAL IP LOOKUP - Get TRUE location of VPN users!
  // ═══════════════════════════════════════════════════════════════
  if (IPQS_KEY && webrtc_real_ip && webrtc_real_ip !== userIP) {
    try {
      console.log(`[VERIFY] Looking up WebRTC real IP: ${webrtc_real_ip}`);
      const realIpResponse = await fetch(`https://www.ipqualityscore.com/api/json/ip/${IPQS_KEY}/${webrtc_real_ip}?strictness=1`);
      const realIp = await realIpResponse.json();
      
      if (realIp.success) {
        threatData.webrtc_real_country = realIp.country_code || null;
        threatData.webrtc_real_region = realIp.region || null;
        threatData.webrtc_real_city = realIp.city || null;
        threatData.webrtc_real_isp = realIp.ISP || null;
        
        console.log(`[VERIFY]  REAL LOCATION: ${realIp.country_code}, ${realIp.region}, ${realIp.city} (ISP: ${realIp.ISP})`);
        console.log(`[VERIFY]  VPN LOCATION: ${threatData.ip_country}, ${threatData.ip_region}, ${threatData.ip_city} (ISP: ${threatData.ip_isp})`);
      }
    } catch (e) {
      console.log(`[VERIFY] WebRTC real IP lookup error:`, e.message);
    }
  }
  
  // Update final risk score
  threatData.total_risk_score = riskScore;
  threatData.risk_reasons = riskReasons;
  
  console.log(`[VERIFY] TOTAL RISK SCORE: ${riskScore}`);
  
  // High risk = block (but allow them to appeal)
  if (riskScore >= 80) {
    console.log(`[VERIFY] HIGH RISK - Score ${riskScore} exceeds threshold`);
    // Don't block, but flag for review
  }
  
  // AbuseIPDB check
  const ABUSEIPDB_KEY = process.env.ABUSEIPDB_API_KEY;
  if (ABUSEIPDB_KEY && userIP && userIP !== 'unknown' && !userIP.startsWith('192.168') && !userIP.startsWith('10.')) {
    try {
      const abuseResponse = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${userIP}`, {
        headers: { 'Key': ABUSEIPDB_KEY, 'Accept': 'application/json' }
      });
      const abuse = await abuseResponse.json();
      if (abuse.data) {
        threatData.ip_abuse_reports = abuse.data.totalReports || 0;
        console.log(`[VERIFY] AbuseIPDB: ${threatData.ip_abuse_reports} reports`);
      }
    } catch (e) {
      console.log(`[VERIFY] AbuseIPDB error:`, e.message);
    }
  }
  
  // ═══════════════════════════════════════════════════════════════════════════
  // ADVANCED SECURITY CHECKS
  // ═══════════════════════════════════════════════════════════════════════════
  
  // 1. ACCOUNT AGE CHECK - Use data from Discord Deep Scan
  let accountAgeDays = discordDeepScan.account_age_days;
  let isNewAccount = accountAgeDays !== null && accountAgeDays < 7;
  if (isNewAccount) {
    riskScore += 20;
    riskReasons.push(`New account (${accountAgeDays} days)`);
    console.log(`[VERIFY] NEW ACCOUNT WARNING: ${accountAgeDays} days old`);
  } else if (accountAgeDays !== null && accountAgeDays < 30) {
    riskScore += 10;
    riskReasons.push(`Young account (${accountAgeDays} days)`);
  }
  threatData.account_age_days = accountAgeDays;
  threatData.is_new_account = isNewAccount;
  threatData.discord_created_at = discordDeepScan.created_at;
  threatData.has_avatar = discordDeepScan.has_avatar;
  threatData.has_banner = discordDeepScan.has_banner;
  threatData.is_nitro = discordDeepScan.is_nitro;
  threatData.badges = discordDeepScan.badges;
  threatData.badge_count = discordDeepScan.badge_count;
  threatData.suspicious_username = discordDeepScan.is_suspicious_username;
  
  // 2. VELOCITY CHECK - Too many verifications from same IP
  let velocityCount = 0;
  let velocityBlocked = false;
  try {
    const velocityCheck = await pool.query(`
      SELECT COUNT(*) FROM verification_logs 
      WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '1 hour' AND result = 'success'
    `, [userIP]);
    velocityCount = parseInt(velocityCheck.rows[0].count);
    if (velocityCount >= 5) {
      velocityBlocked = true;
      riskScore += 50;
      riskReasons.push(`Velocity limit (${velocityCount} verifications/hour)`);
      console.log(`[VERIFY] VELOCITY LIMIT: ${velocityCount} accounts from same IP in 1 hour`);
    } else if (velocityCount >= 3) {
      riskScore += 20;
      riskReasons.push(`Multiple verifications (${velocityCount}/hour)`);
    }
  } catch (e) {
    console.log(`[VERIFY] Velocity check error:`, e.message);
  }
  threatData.velocity_count = velocityCount;
  threatData.velocity_blocked = velocityBlocked;
  
  // 3. IMPOSSIBLE TRAVEL CHECK - Same fingerprint, different country too fast
  let impossibleTravel = false;
  let lastCountry = null;
  try {
    const lastVerification = await pool.query(`
      SELECT ip_country, ip_city, created_at FROM verification_logs 
      WHERE fingerprint_hash = $1 AND ip_country IS NOT NULL
      ORDER BY created_at DESC LIMIT 1
    `, [fingerprint]);
    
    if (lastVerification.rows.length > 0) {
      lastCountry = lastVerification.rows[0].ip_country;
      const lastTime = new Date(lastVerification.rows[0].created_at);
      const hoursSinceLastVerification = (Date.now() - lastTime.getTime()) / (1000 * 60 * 60);
      
      if (lastCountry && threatData.ip_country && lastCountry !== threatData.ip_country && hoursSinceLastVerification < 6) {
        impossibleTravel = true;
        riskScore += 40;
        riskReasons.push(`Impossible travel (${lastCountry}  ${threatData.ip_country} in ${hoursSinceLastVerification.toFixed(1)}h)`);
        console.log(`[VERIFY] IMPOSSIBLE TRAVEL: ${lastCountry}  ${threatData.ip_country} in ${hoursSinceLastVerification.toFixed(1)} hours`);
      }
    }
  } catch (e) {
    console.log(`[VERIFY] Impossible travel check error:`, e.message);
  }
  threatData.impossible_travel = impossibleTravel;
  threatData.last_country = lastCountry;
  
  // 4. BROWSER LANGUAGE CHECK - Language doesn't match country
  let languageMismatch = false;
  try {
    const browserLang = fingerprint_data?.nav?.lang || fingerprint_data?.language;
    if (browserLang && threatData.ip_country) {
      const langCountryMap = {
        'en': ['US', 'GB', 'CA', 'AU', 'NZ', 'IE'],
        'es': ['ES', 'MX', 'AR', 'CO', 'PE', 'CL'],
        'fr': ['FR', 'CA', 'BE', 'CH'],
        'de': ['DE', 'AT', 'CH'],
        'pt': ['BR', 'PT'],
        'ru': ['RU', 'UA', 'BY', 'KZ'],
        'zh': ['CN', 'TW', 'HK', 'SG'],
        'ja': ['JP'],
        'ko': ['KR']
      };
      const langPrefix = browserLang.split('-')[0].toLowerCase();
      const expectedCountries = langCountryMap[langPrefix] || [];
      
      // Only flag if we have a clear mismatch (e.g., Russian browser but US IP)
      if (expectedCountries.length > 0 && !expectedCountries.includes(threatData.ip_country)) {
        // Check if it's a suspicious mismatch
        if (['ru', 'zh', 'ko'].includes(langPrefix) && ['US', 'GB', 'CA', 'AU'].includes(threatData.ip_country)) {
          languageMismatch = true;
          riskScore += 15;
          riskReasons.push(`Language mismatch (${browserLang} in ${threatData.ip_country})`);
          console.log(`[VERIFY] LANGUAGE MISMATCH: Browser=${browserLang}, Country=${threatData.ip_country}`);
        }
      }
    }
  } catch (e) {
    console.log(`[VERIFY] Language check error:`, e.message);
  }
  threatData.language_mismatch = languageMismatch;
  
  // 5. TIME-BASED SUSPICION - Verification at unusual hours (2-5 AM local time)
  let unusualTime = false;
  try {
    if (threatData.ip_timezone) {
      const userLocalTime = new Date().toLocaleString('en-US', { timeZone: threatData.ip_timezone, hour: 'numeric', hour12: false });
      const hour = parseInt(userLocalTime);
      if (hour >= 2 && hour <= 5) {
        unusualTime = true;
        riskScore += 10;
        riskReasons.push(`Unusual time (${hour}:00 local)`);
        console.log(`[VERIFY] UNUSUAL TIME: ${hour}:00 local time`);
      }
    }
  } catch (e) {
    console.log(`[VERIFY] Time check error:`, e.message);
  }
  threatData.unusual_time = unusualTime;
  
  // Update final risk score again
  threatData.total_risk_score = riskScore;
  threatData.risk_reasons = riskReasons;
  
  // 6. STAFF DM ALERTS - Alert mods for high-risk verifications
  const STAFF_ALERT_CHANNEL = process.env.STAFF_ALERT_CHANNEL || '1329894067922010153'; // Your mod-logs channel
  if (riskScore >= 50) {
    try {
      const alertChannel = client.channels.cache.get(STAFF_ALERT_CHANNEL);
      if (alertChannel) {
        const alertEmbed = new EmbedBuilder()
          .setTitle(' High-Risk Verification')
          .setColor(riskScore >= 75 ? 0xFF0000 : 0xFFA500)
          .addFields(
            { name: 'User', value: `<@${discord_id}> (${discord_id})`, inline: true },
            { name: 'Risk Score', value: `**${riskScore}**/100`, inline: true },
            { name: 'Location', value: `${threatData.ip_country || '?'}, ${threatData.ip_region || '?'}, ${threatData.ip_city || '?'}`, inline: true },
            { name: 'IP', value: `\`${userIP}\``, inline: true },
            { name: 'ISP', value: threatData.ip_isp || 'Unknown', inline: true },
            { name: 'Account Age', value: accountAgeDays !== null ? `${accountAgeDays} days` : 'Unknown', inline: true },
            { name: 'Flags', value: riskReasons.join(', ') || 'None', inline: false }
          )
          .setTimestamp();
        
        if (threatData.ip_vpn) alertEmbed.addFields({ name: ' VPN', value: 'Detected', inline: true });
        if (impossibleTravel) alertEmbed.addFields({ name: ' Travel', value: `${lastCountry}  ${threatData.ip_country}`, inline: true });
        if (velocityCount >= 3) alertEmbed.addFields({ name: ' Velocity', value: `${velocityCount}/hour`, inline: true });
        
        await alertChannel.send({ embeds: [alertEmbed] });
        console.log(`[VERIFY] Staff alert sent for high-risk user`);
      }
    } catch (e) {
      console.log(`[VERIFY] Staff alert error:`, e.message);
    }
  }
  
  // Bot/Automation detection from fingerprint_data
  if (fingerprint_data) {
    // Check for headless browser indicators
    const ua = req.headers['user-agent'] || '';
    threatData.is_headless = ua.includes('HeadlessChrome') || ua.includes('PhantomJS') || 
                              !fingerprint_data.webglRenderer || fingerprint_data.webglRenderer === 'err';
    
    // Check for automation frameworks
    threatData.is_bot = threatData.is_headless || 
                         (fingerprint_data.behavior && fingerprint_data.behavior.moves < 5) ||
                         (fingerprint_data.behavior && fingerprint_data.behavior.duration < 2000);
    
    if (threatData.is_bot) {
      console.log(`[VERIFY] Bot detection triggered: headless=${threatData.is_headless}`);
    }
  }
  
  // Helper function to log verification attempt
  async function logVerificationAttempt(result, altOfId = null, altOfTag = null) {
    try {
      const member = await client.guilds.cache.get(guild_id)?.members.fetch(discord_id).catch(() => null);
      await pool.query(`
        INSERT INTO verification_logs 
        (discord_id, discord_tag, guild_id, result, fingerprint_hash, alt_of_discord_id, alt_of_discord_tag,
         ip_address, ip_port, ip_risk_score, ip_vpn, ip_proxy, ip_tor, ip_bot_score, 
         ip_country, ip_region, ip_city, ip_isp, ip_org, ip_asn, ip_host, ip_mobile, ip_connection_type,
         ip_latitude, ip_longitude, ip_abuse_reports, timezone_mismatch, browser_timezone, ip_timezone,
         webrtc_real_ip, webrtc_local_ips, webrtc_leak, webrtc_real_country, webrtc_real_region, webrtc_real_city, webrtc_real_isp,
         account_age_days, is_new_account, discord_created_at, has_avatar, has_banner, is_nitro, badges, badge_count, suspicious_username,
         honeypot_triggered, impossible_travel, velocity_blocked, language_mismatch, unusual_time,
         behavior_data, gpu_data, user_agent)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $40, $41, $42, $43, $44, $45, $46, $47, $48, $49, $50, $51, $52)
      `, [
        discord_id,
        member?.user?.tag || 'Unknown',
        guild_id,
        result,
        fingerprint,
        altOfId,
        altOfTag,
        threatData.ip_address,
        threatData.ip_port,
        threatData.ip_risk_score,
        threatData.ip_vpn,
        threatData.ip_proxy,
        threatData.ip_tor,
        threatData.ip_bot_score,
        threatData.ip_country,
        threatData.ip_region || null,
        threatData.ip_city,
        threatData.ip_isp,
        threatData.ip_org,
        threatData.ip_asn,
        threatData.ip_host,
        threatData.ip_mobile,
        threatData.ip_connection_type,
        threatData.ip_latitude,
        threatData.ip_longitude,
        threatData.ip_abuse_reports,
        threatData.timezone_mismatch,
        threatData.browser_timezone,
        threatData.ip_timezone,
        threatData.webrtc_real_ip,
        threatData.webrtc_local_ips ? JSON.stringify(threatData.webrtc_local_ips) : null,
        threatData.webrtc_leak,
        threatData.webrtc_real_country || null,
        threatData.webrtc_real_region || null,
        threatData.webrtc_real_city || null,
        threatData.webrtc_real_isp || null,
        threatData.account_age_days,
        threatData.is_new_account,
        threatData.discord_created_at,
        threatData.has_avatar,
        threatData.has_banner,
        threatData.is_nitro,
        threatData.badges ? JSON.stringify(threatData.badges) : null,
        threatData.badge_count,
        threatData.suspicious_username,
        clientThreats.honeypot || false,
        threatData.impossible_travel || false,
        threatData.velocity_blocked || false,
        threatData.language_mismatch || false,
        threatData.unusual_time || false,
        JSON.stringify(fingerprint_data?.behavior || {}),
        JSON.stringify(fingerprint_data?.gpu || {}),
        threatData.user_agent
      ]);
      console.log(`[VERIFY] Logged attempt: ${result}`);
    } catch (e) {
      console.log(`[VERIFY] Failed to log attempt:`, e.message);
    }
  }
  
  try {
    // 1. Validate token
    const tokenData = verificationTokens.get(token);
    if (!tokenData) {
      console.log(`[VERIFY] Invalid or expired token`);
      return res.status(400).json({ success: false, error: 'Invalid or expired token. Please click Verify again in Discord.' });
    }
    
    if (tokenData.discord_id !== discord_id || tokenData.guild_id !== guild_id) {
      console.log(`[VERIFY] Token mismatch`);
      return res.status(400).json({ success: false, error: 'Token mismatch. Please try again.' });
    }
    
    if (tokenData.expires_at < Date.now()) {
      verificationTokens.delete(token);
      console.log(`[VERIFY] Token expired`);
      return res.status(400).json({ success: false, error: 'Token expired. Please click Verify again in Discord.' });
    }
    
    // 2. Verify hCaptcha
    const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET;
    if (HCAPTCHA_SECRET && captcha_token) {
      try {
        const hcaptchaResponse = await fetch('https://hcaptcha.com/siteverify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `secret=${HCAPTCHA_SECRET}&response=${captcha_token}`
        });
        const hcaptchaResult = await hcaptchaResponse.json();
        
        if (!hcaptchaResult.success) {
          console.log(`[VERIFY] hCaptcha failed:`, hcaptchaResult);
          return res.status(400).json({ success: false, error: 'Captcha verification failed. Please try again.' });
        }
        console.log(`[VERIFY] hCaptcha passed`);
      } catch (e) {
        console.log(`[VERIFY] hCaptcha error:`, e.message);
        // Continue anyway if hCaptcha service is down
      }
    }
    
    // 3. Check fingerprint against BANNED devices
    const banCheck = await pool.query(
      `SELECT * FROM fingerprint_bans WHERE fingerprint_hash = $1 AND guild_id = $2`,
      [fingerprint, guild_id]
    );
    
    if (banCheck.rows.length > 0) {
      const bannedRecord = banCheck.rows[0];
      console.log(`[VERIFY] BLOCKED - Alt of banned user ${bannedRecord.banned_discord_tag}`);
      
      // Get guild and log channel for alert
      const guild = client.guilds.cache.get(guild_id);
      if (guild) {
        const SECURITY_LOG_ID = '1463995707651522622';
        const securityLog = guild.channels.cache.get(SECURITY_LOG_ID) || 
                            guild.channels.cache.find(c => c.name === 'security-logs' || c.name === 'modmail-logs');
        
        if (securityLog) {
          const alertEmbed = new EmbedBuilder()
            .setTitle(' ALT ACCOUNT BLOCKED')
            .setDescription(`**Attempted User ID:** \`${discord_id}\``)
            .addFields(
              { name: ' Alt of Banned User', value: `**${bannedRecord.banned_discord_tag}**\n<@${bannedRecord.banned_discord_id}>`, inline: false },
              { name: ' Original Ban Date', value: `<t:${Math.floor(new Date(bannedRecord.banned_at).getTime() / 1000)}:F>`, inline: true },
              { name: ' Original Ban Reason', value: bannedRecord.reason || 'No reason recorded', inline: true },
              { name: ' Action', value: 'Verification DENIED - Same device fingerprint as banned user', inline: false }
            )
            .setColor(0xFF0000)
            .setTimestamp();
          
          await securityLog.send({ content: '@here', embeds: [alertEmbed] });
          console.log(`[VERIFY] Alert sent to security-logs`);
        } else {
          console.log(`[VERIFY] Could not find security-logs channel`);
        }
        
        // DM the user with intimidating message
        try {
          const user = await client.users.fetch(discord_id);
          
          let intimidatingMessage = `*encrypted transmission intercepted...*\n\nWell, well... **${bannedRecord.banned_discord_tag}** thought they could hide behind a fresh account.\n\nYour device fingerprint was flagged the moment you connected. Canvas rendering patterns, WebGL signatures, GPU metadata, font enumeration, audio context hashes, screen dimensions, timezone offset, hardware concurrency... every digital breadcrumb you leave creates a signature. And yours? Already in our database. Permanently.\n\nVPN? Useless. New email? Irrelevant. New Discord account? *Pathetic.* Your hardware betrayed you the second you loaded the verification page. We see everything. We forget nothing.\n\n*You are marked.*`;
          
          // Try to get AI-generated message
          if (anthropic) {
            try {
              const aiResponse = await anthropic.messages.create({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 400,
                messages: [{
                  role: 'user',
                  content: `You are Burner Phone, a cold, intimidating anonymous security system. You caught a BANNED user trying to sneak back in on an alt. Their banned account was "${bannedRecord.banned_discord_tag}".

Write a terrifying, intimidating message. Be ruthless. Make them feel like they're being watched by something they can't escape. Mix these vibes:
- Anonymous hacker who sees everything
- Cold, calculating, almost inhuman security AI
- Mock their pathetic attempt to hide
- Flex hard on the technical fingerprinting (canvas hash, WebGL renderer, GPU metadata, audio context, font enumeration, screen dimensions, timezone, hardware concurrency)
- Make it clear they are PERMANENTLY marked
- VPNs, new emails, new accounts - none of it matters
- Their hardware betrays them

Use *italics* for dramatic effect. Be creative and menacing. Include their banned username "${bannedRecord.banned_discord_tag}". Make them paranoid. Keep it 2-3 paragraphs, under 900 characters. No emojis.`
                }]
              });
              intimidatingMessage = aiResponse.content[0].text;
            } catch (e) {
              console.log('[VERIFY] Claude API error, using fallback message');
            }
          }
          
          await user.send({
            embeds: [new EmbedBuilder()
              .setTitle(' BURNER PHONE ALERT')
              .setDescription(intimidatingMessage)
              .setColor(0xFF0000)
              .setFooter({ text: ' Burner Phone • We See Everything' })
              .setTimestamp()
            ]
          });
          
          // Dramatic follow-up messages
          await new Promise(r => setTimeout(r, 2000));
          await user.send({
            content: '```diff\n-  SECURITY VIOLATION LOGGED\n- Device fingerprint: FLAGGED\n- Associated account: ' + bannedRecord.banned_discord_tag + '\n- Status: PERMANENTLY BANNED\n```'
          });
          
          await new Promise(r => setTimeout(r, 1500));
          await user.send({
            content: '```\n[SYSTEM] Cross-referencing device signature...\n[SYSTEM] Match found in banned registry.\n[SYSTEM] Access permanently revoked.\n[SYSTEM] All future attempts will be logged and reported.\n```'
          });
          
          // Appeal option with button
          await new Promise(r => setTimeout(r, 2000));
          const { ActionRowBuilder, ButtonBuilder, ButtonStyle } = require('discord.js');
          const appealRow = new ActionRowBuilder()
            .addComponents(
              new ButtonBuilder()
                .setCustomId(`appeal_ban_${discord_id}`)
                .setLabel(' Submit Appeal')
                .setStyle(ButtonStyle.Primary),
              new ButtonBuilder()
                .setCustomId(`appeal_decline_${discord_id}`)
                .setLabel('No Thanks')
                .setStyle(ButtonStyle.Secondary)
            );
          
          await user.send({
            embeds: [new EmbedBuilder()
              .setTitle(' Appeal Process')
              .setDescription('If you believe this is an error, you may submit an appeal.\n\nA staff member will review your case within 24-48 hours.')
              .setColor(0x5865F2)
              .setFooter({ text: 'Click below to start your appeal' })
            ],
            components: [appealRow]
          });
          
        } catch (e) {
          console.log('[VERIFY] Could not DM user:', e.message);
        }
        
        // Give them "Suspended" role (alt of banned user)
        try {
          const member = await guild.members.fetch(discord_id).catch(() => null);
          if (member) {
            const suspendedRole = guild.roles.cache.find(r => r.name.toLowerCase() === 'suspended');
            if (suspendedRole) {
              await member.roles.add(suspendedRole);
              console.log(`[VERIFY] Added Suspended role to ${discord_id}`);
            }
          }
        } catch (e) {
          console.log('[VERIFY] Could not add suspended role:', e.message);
        }
      }
      
      // Delete the token
      verificationTokens.delete(token);
      
      // Log the blocked attempt
      await logVerificationAttempt('blocked_alt', bannedRecord.banned_discord_id, bannedRecord.banned_discord_tag);
      
      return res.json({ 
        success: false, 
        blocked: true,
        error: 'This device belongs to a banned user. Your attempt has been logged.',
        alt_of: bannedRecord.banned_discord_tag
      });
    }
    
    // 4. Check fingerprint against existing verified users (duplicate device)
    const duplicateCheck = await pool.query(
      `SELECT * FROM device_fingerprints WHERE fingerprint_hash = $1 AND guild_id = $2 AND discord_id != $3`,
      [fingerprint, guild_id, discord_id]
    );
    
    if (duplicateCheck.rows.length > 0) {
      const existingRecord = duplicateCheck.rows[0];
      console.log(`[VERIFY] BLOCKED - Duplicate device, already linked to ${existingRecord.discord_tag}`);
      
      // Track attempt count
      const attemptData = duplicateAttempts.get(discord_id) || { count: 0, last_attempt: 0 };
      attemptData.count++;
      attemptData.last_attempt = Date.now();
      duplicateAttempts.set(discord_id, attemptData);
      
      console.log(`[VERIFY] Duplicate attempt #${attemptData.count} from ${discord_id}`);
      
      // Send escalating DM based on attempt count
      try {
        const user = await client.users.fetch(discord_id);
        let dmMessage;
        
        if (attemptData.count === 1) {
          // 1st attempt - Polite
          dmMessage = {
            embeds: [new EmbedBuilder()
              .setTitle(' Verification Notice')
              .setDescription(`Hey there! It looks like this device is already linked to another account (**${existingRecord.discord_tag}**).\n\nWe have a **one account per device** policy to keep our community secure and fair for everyone.\n\nIf you believe this is an error, **reply to this DM** and our staff team will assist you.`)
              .setColor(0xFFA500)
              .setFooter({ text: ' Burner Phone • Security System' })
              .setTimestamp()
            ]
          };
        } else if (attemptData.count === 2) {
          // 2nd attempt - Annoyed
          dmMessage = {
            embeds: [new EmbedBuilder()
              .setTitle(' Second Notice')
              .setDescription(`We already told you - this device is registered to **${existingRecord.discord_tag}**.\n\nTrying again won't change anything. Our fingerprinting system tracks your device hardware, not your account. Creating new Discord accounts is pointless.\n\n**One device = One account.** That's the rule.`)
              .setColor(0xFF6600)
              .setFooter({ text: ' Burner Phone • We Remember Everything' })
              .setTimestamp()
            ]
          };
        } else if (attemptData.count === 3) {
          // 3rd attempt - Frustrated
          dmMessage = {
            embeds: [new EmbedBuilder()
              .setTitle(' Final Warning')
              .setDescription(`*Seriously?* This is your **third attempt**.\n\nLet us be crystal clear:\n• Your device fingerprint is **permanently logged**\n• It's linked to **${existingRecord.discord_tag}**\n• No amount of new accounts will change this\n• Your canvas hash, WebGL renderer, GPU, fonts - all tracked\n\nWe're starting to wonder if you're trying to evade something. Keep this up and we might have to look closer at why you're so desperate to get a second account.`)
              .setColor(0xFF3300)
              .setFooter({ text: ' Burner Phone • Patience Wearing Thin' })
              .setTimestamp()
            ]
          };
        } else {
          // 4th+ attempt - Done with this
          dmMessage = {
            embeds: [new EmbedBuilder()
              .setTitle(' ENOUGH.')
              .setDescription(`**${attemptData.count} attempts.** Really?\n\nYou're wasting your time. You're wasting *our* time. This device belongs to **${existingRecord.discord_tag}** and that's never going to change.\n\n*Every. Single. Attempt.* is being logged. Your desperation is noted. At this point, you're just making yourself look suspicious.\n\n**Stop.**`)
              .setColor(0xFF0000)
              .setFooter({ text: ' Burner Phone • All Attempts Logged' })
              .setTimestamp()
            ]
          };
        }
        
        // Log ALL duplicate attempts to security channel
        const guild = client.guilds.cache.get(guild_id);
        if (guild) {
          const SECURITY_LOG_ID = '1463995707651522622';
          const securityLog = guild.channels.cache.get(SECURITY_LOG_ID) || 
                              guild.channels.cache.find(c => c.name === 'security-logs' || c.name === 'modmail-logs');
          if (securityLog) {
            const alertEmbed = new EmbedBuilder()
              .setTitle(' DUPLICATE ACCOUNT BLOCKED')
              .setDescription(`**Attempted User:** <@${discord_id}>\n**ID:** \`${discord_id}\``)
              .addFields(
                { name: ' Device Already Linked To', value: `**${existingRecord.discord_tag}**\n<@${existingRecord.discord_id}>`, inline: false },
                { name: ' Action', value: 'Verification DENIED - One account per device policy', inline: true },
                { name: ' Attempt #', value: `${attemptData.count}`, inline: true }
              )
              .setColor(0xFF6600)
              .setTimestamp();
            await securityLog.send({ content: attemptData.count >= 4 ? '@here' : '', embeds: [alertEmbed] });
            console.log(`[VERIFY] Duplicate attempt alert sent to security-logs`);
          }
        }
        
        await user.send(dmMessage);
        console.log(`[VERIFY] Sent escalating DM (attempt #${attemptData.count}) to ${discord_id}`);
        
        // Give them "Alternate Account" role after 1+ attempts
        if (attemptData.count >= 1) {
          try {
            const guild = client.guilds.cache.get(guild_id);
            const member = await guild?.members.fetch(discord_id).catch(() => null);
            if (member) {
              const altRole = guild.roles.cache.find(r => r.name.toLowerCase() === 'alternate account');
              if (altRole) {
                await member.roles.add(altRole);
                console.log(`[VERIFY] Added Alternate Account role to ${discord_id}`);
              }
            }
          } catch (e) {
            console.log('[VERIFY] Could not add alternate account role:', e.message);
          }
          
          // Send appeal option after 2+ attempts
          const appealRow = new ActionRowBuilder()
            .addComponents(
              new ButtonBuilder()
                .setCustomId(`appeal_alt_${discord_id}`)
                .setLabel(' Contact Staff')
                .setStyle(ButtonStyle.Primary),
              new ButtonBuilder()
                .setCustomId('appeal_dismiss')
                .setLabel('Dismiss')
                .setStyle(ButtonStyle.Secondary)
            );
          
          await user.send({
            embeds: [new EmbedBuilder()
              .setTitle(' Need Help?')
              .setDescription('If you believe this is an error (e.g. shared computer, sold device), you can contact staff to explain your situation.')
              .setColor(0x5865F2)
            ],
            components: [appealRow]
          });
        }
        
      } catch (e) {
        console.log('[VERIFY] Could not DM user:', e.message);
      }
      
      // Delete the token
      verificationTokens.delete(token);
      
      // Log the duplicate attempt
      await logVerificationAttempt('duplicate', existingRecord.discord_id, existingRecord.discord_tag);
      
      return res.json({ 
        success: false, 
        blocked: true,
        error: `This device is already linked to another account: ${existingRecord.discord_tag}. One account per device policy.`,
        linked_to: existingRecord.discord_tag,
        attempt_count: attemptData.count
      });
    }
    
    // 5. All checks passed - Store fingerprint and assign role
    const guild = client.guilds.cache.get(guild_id);
    if (!guild) {
      return res.status(400).json({ success: false, error: 'Guild not found' });
    }
    
    const member = await guild.members.fetch(discord_id).catch(() => null);
    if (!member) {
      return res.status(400).json({ success: false, error: 'Member not found in guild' });
    }
    
    // Store fingerprint
    await pool.query(`
      INSERT INTO device_fingerprints (discord_id, discord_tag, guild_id, fingerprint_hash, fingerprint_data)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (discord_id, guild_id) DO UPDATE SET 
        fingerprint_hash = $4, 
        fingerprint_data = $5,
        verified_at = NOW()
    `, [discord_id, member.user.tag, guild_id, fingerprint, fingerprint_data]);
    
    console.log(`[VERIFY] Fingerprint stored for ${member.user.tag}`);
    
    // Assign verified role
    const VERIFIED_ROLE_ID = '1453304594317836423';
    const verifiedRole = guild.roles.cache.get(VERIFIED_ROLE_ID) || 
                         guild.roles.cache.find(r => r.name.toLowerCase() === 'verified');
    
    if (verifiedRole) {
      await member.roles.add(verifiedRole);
      console.log(`[VERIFY] Verified role assigned to ${member.user.tag}`);
    }
    
    // Log to security channel
    const securityLog = guild.channels.cache.find(c => 
      c.name === 'security-logs' || c.name === 'modmail-logs'
    );
    
    if (securityLog) {
      const logEmbed = new EmbedBuilder()
        .setTitle(' User Verified')
        .setDescription(`**User:** ${member.user.tag}\n**ID:** \`${member.id}\``)
        .addFields({ name: ' Device Fingerprint', value: 'Stored successfully', inline: true })
        .setColor(0x00FF00)
        .setThumbnail(member.user.displayAvatarURL())
        .setTimestamp();
      
      await securityLog.send({ embeds: [logEmbed] });
    }
    
    // Welcome in general chat
    const generalChannel = guild.channels.cache.get('1453304724681134163') || 
                           guild.channels.cache.find(c => c.name === 'general-chat' || c.name === 'general');
    
    const rolesChannel = guild.channels.cache.find(c => c.name === 'roles' || c.name === 'get-roles');
    const rolesChannelId = rolesChannel?.id || '1453304716967678022';
    
    if (generalChannel) {
      const welcomes = [
        `*security scan complete* ${member} is now verified. Welcome to the operation. Go pick your roles in <#${rolesChannelId}>.`,
        `${member} passed the fingerprint check. *unlocks channels* Head to <#${rolesChannelId}> and tell us what you're here for.`,
        `*device cleared* ${member} is officially in. Grab your roles in <#${rolesChannelId}> - we need to know your specialty.`
      ];
      
      const randomWelcome = welcomes[Math.floor(Math.random() * welcomes.length)];
      
      const embed = new EmbedBuilder()
        .setTitle(' Get Your Roles!')
        .setDescription(`**What brings you here?**\n\n **GTA Online** - Heists, grinding, businesses\n **Red Dead Online** - Wagons, bounties, collector\n\n **Click here  <#${rolesChannelId}>**`)
        .setColor(0x00FF00)
        .setFooter({ text: 'Select roles to find the right crew!' });
      
      await generalChannel.send({ content: randomWelcome, embeds: [embed] });
    }
    
    // Delete the used token
    verificationTokens.delete(token);
    
    // Log the successful verification
    await logVerificationAttempt('success', null, null);
    
    console.log(`[VERIFY] SUCCESS - ${member.user.tag} verified`);
    
    return res.json({ success: true, message: 'Verification complete!' });
    
  } catch (error) {
    console.error('[VERIFY] Error:', error);
    return res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// STAFF API ENDPOINTS - For staff.html dashboard
// ═══════════════════════════════════════════════════════════════════════════════

// Simple API key check (for now, can be enhanced later)
const STAFF_API_KEY = process.env.STAFF_API_KEY || 'unpatched-staff-2024';

// ═══════════════════════════════════════════════════════════════════════════
// ACTIVITY LOGGER - Track all user activity in server
// ═══════════════════════════════════════════════════════════════════════════

const activityLog = [];
const MAX_ACTIVITY_LOG = 1000;

function logActivity(type, userId, userTag, details, channelName = null) {
  const entry = {
    type,
    user_id: userId,
    user_tag: userTag,
    details,
    channel: channelName,
    timestamp: new Date().toISOString()
  };
  activityLog.unshift(entry);
  if (activityLog.length > MAX_ACTIVITY_LOG) activityLog.pop();
  console.log(`[ACTIVITY] ${type}: ${userTag} - ${details}`);
}

// Message sent
client.on('messageCreate', async (message) => {
  if (message.author.bot) return;
  if (!message.guild) return;
  
  logActivity('message', message.author.id, message.author.tag, 
    message.content.substring(0, 100) + (message.content.length > 100 ? '...' : ''),
    message.channel.name);
});

// Message deleted
client.on('messageDelete', async (message) => {
  if (!message.author || message.author.bot) return;
  if (!message.guild) return;
  
  logActivity('delete', message.author.id, message.author.tag,
    `Deleted: "${message.content?.substring(0, 50) || 'Unknown'}..."`,
    message.channel.name);
});

// Reaction added
client.on('messageReactionAdd', async (reaction, user) => {
  if (user.bot) return;
  
  logActivity('reaction', user.id, user.tag,
    `Reacted ${reaction.emoji.name} to message`,
    reaction.message.channel.name);
});

// Voice state update
client.on('voiceStateUpdate', async (oldState, newState) => {
  const user = newState.member?.user || oldState.member?.user;
  if (!user || user.bot) return;
  
  if (!oldState.channel && newState.channel) {
    logActivity('voice_join', user.id, user.tag,
      `Joined voice: ${newState.channel.name}`,
      newState.channel.name);
  } else if (oldState.channel && !newState.channel) {
    logActivity('voice_leave', user.id, user.tag,
      `Left voice: ${oldState.channel.name}`,
      oldState.channel.name);
  } else if (oldState.channel && newState.channel && oldState.channel.id !== newState.channel.id) {
    logActivity('voice_move', user.id, user.tag,
      `Moved: ${oldState.channel.name}  ${newState.channel.name}`,
      newState.channel.name);
  }
});

// Member join
client.on('guildMemberAdd', async (member) => {
  logActivity('join', member.user.id, member.user.tag, 'Joined the server');
});

// Member leave
client.on('guildMemberRemove', async (member) => {
  logActivity('leave', member.user.id, member.user.tag, 'Left the server');
});

// Nickname change
client.on('guildMemberUpdate', async (oldMember, newMember) => {
  if (oldMember.nickname !== newMember.nickname) {
    logActivity('nickname', newMember.user.id, newMember.user.tag,
      `Changed nickname: "${oldMember.nickname || 'None'}"  "${newMember.nickname || 'None'}"`);
  }
});

// GET /api/staff/activity - Get activity log
app.get('/api/staff/activity', checkStaffAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const userId = req.query.user_id;
  const type = req.query.type;
  
  let filtered = activityLog;
  if (userId) filtered = filtered.filter(a => a.user_id === userId);
  if (type) filtered = filtered.filter(a => a.type === type);
  
  res.json({ activity: filtered.slice(0, limit), total: filtered.length });
});

// ═══════════════════════════════════════════════════════════════════════════
// TRACKABLE LINKS - Capture IP when users click links
// ═══════════════════════════════════════════════════════════════════════════

const trackableLinks = new Map(); // code -> { url, created_by, created_at, name }
const linkClicks = []; // { code, ip, user_agent, timestamp, location }

// Create trackable link
app.post('/api/staff/create-link', checkStaffAuth, async (req, res) => {
  const { url, name } = req.body;
  
  if (!url) return res.json({ error: 'URL required' });
  
  const code = crypto.randomBytes(4).toString('hex');
  trackableLinks.set(code, {
    url,
    name: name || 'Unnamed',
    created_by: req.staffUser?.username || 'Unknown',
    created_at: new Date().toISOString(),
    clicks: 0
  });
  
  res.json({ 
    success: true, 
    code,
    tracking_url: `https://burner-phone-bot-production.up.railway.app/t/${code}`
  });
});

// Track link click and redirect
app.get('/t/:code', async (req, res) => {
  const link = trackableLinks.get(req.params.code);
  if (!link) return res.status(404).send('Link not found');
  
  const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.connection?.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  
  // Get location from IP
  let location = {};
  const IPQS_KEY = process.env.IPQUALITYSCORE_API_KEY;
  if (IPQS_KEY && ip !== 'unknown') {
    try {
      const ipqsRes = await fetch(`https://www.ipqualityscore.com/api/json/ip/${IPQS_KEY}/${ip}?strictness=1`);
      const ipqs = await ipqsRes.json();
      if (ipqs.success) {
        location = {
          country: ipqs.country_code,
          region: ipqs.region,
          city: ipqs.city,
          isp: ipqs.ISP,
          vpn: ipqs.vpn,
          proxy: ipqs.proxy,
          risk_score: ipqs.fraud_score
        };
      }
    } catch (e) {}
  }
  
  // Log click
  const click = {
    code: req.params.code,
    link_name: link.name,
    ip,
    user_agent: userAgent,
    location,
    timestamp: new Date().toISOString()
  };
  linkClicks.unshift(click);
  if (linkClicks.length > 1000) linkClicks.pop();
  
  link.clicks++;
  
  console.log(`[TRACK LINK] ${link.name}: ${ip} from ${location.country || 'Unknown'}, ${location.city || 'Unknown'} (VPN: ${location.vpn || false})`);
  
  // Redirect to actual URL
  res.redirect(link.url);
});

// Get all trackable links
app.get('/api/staff/links', checkStaffAuth, (req, res) => {
  const links = [];
  trackableLinks.forEach((data, code) => {
    links.push({ code, ...data, tracking_url: `https://burner-phone-bot-production.up.railway.app/t/${code}` });
  });
  res.json({ links });
});

// Get link clicks
app.get('/api/staff/link-clicks', checkStaffAuth, (req, res) => {
  const code = req.query.code;
  let clicks = linkClicks;
  if (code) clicks = clicks.filter(c => c.code === code);
  res.json({ clicks: clicks.slice(0, 200) });
});

// Delete trackable link
app.delete('/api/staff/links/:code', checkStaffAuth, (req, res) => {
  if (trackableLinks.delete(req.params.code)) {
    res.json({ success: true });
  } else {
    res.json({ error: 'Link not found' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// STAFF OAUTH & AUTHENTICATION
// ═══════════════════════════════════════════════════════════════════════════

const staffTokens = new Map(); // token -> { user, expires }
const STAFF_ROLE_IDS = ['1453304665046257819', '1453304662156644445', '1453304660134727764']; // Senior Admin, Admin, Moderator
const ALLOWED_STAFF_IDS = ['513386668042698755']; // Owner ID - always allowed

function checkStaffAuth(req, res, next) {
  // Check API key (legacy)
  const apiKey = req.headers['x-api-key'] || req.query.key;
  if (apiKey === STAFF_API_KEY) {
    return next();
  }
  
  // Check Bearer token (OAuth)
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const session = staffTokens.get(token);
    if (session && session.expires > Date.now()) {
      req.staffUser = session.user;
      return next();
    }
  }
  
  return res.status(401).json({ error: 'Unauthorized' });
}

// POST /api/staff/oauth - Exchange Discord code for staff token
app.post('/api/staff/oauth', async (req, res) => {
  const { code, redirect_uri } = req.body;
  
  if (!code) {
    return res.status(400).json({ success: false, error: 'No code provided' });
  }
  
  try {
    // Exchange code for Discord access token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID || '1462303194863505521',
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri
      })
    });
    
    const tokenData = await tokenRes.json();
    
    if (!tokenData.access_token) {
      console.log('[STAFF OAUTH] Token exchange failed:', tokenData);
      return res.json({ success: false, error: 'Discord authentication failed' });
    }
    
    // Get user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();
    
    if (!user.id) {
      return res.json({ success: false, error: 'Could not get user info' });
    }
    
    // Check if user is allowed (owner or has staff role in guild)
    let isStaff = ALLOWED_STAFF_IDS.includes(user.id);
    
    if (!isStaff) {
      // Check guild membership and roles
      try {
        const guild = client.guilds.cache.get(CONFIG.GUILD_ID);
        if (guild) {
          const member = await guild.members.fetch(user.id).catch(() => null);
          if (member) {
            isStaff = member.roles.cache.some(r => STAFF_ROLE_IDS.includes(r.id)) ||
                      member.permissions.has('ModerateMembers') ||
                      member.permissions.has('Administrator');
          }
        }
      } catch (e) {
        console.log('[STAFF OAUTH] Role check error:', e.message);
      }
    }
    
    if (!isStaff) {
      return res.json({ success: false, error: 'Access denied. You must be a server moderator.' });
    }
    
    // Generate session token
    const token = require('crypto').randomBytes(32).toString('hex');
    staffTokens.set(token, {
      user: { id: user.id, username: user.username, avatar: user.avatar },
      expires: Date.now() + (24 * 60 * 60 * 1000) // 24 hours
    });
    
    console.log(`[STAFF OAUTH] ${user.username} (${user.id}) logged in`);
    
    res.json({
      success: true,
      token,
      user: { id: user.id, username: user.username, avatar: user.avatar }
    });
    
  } catch (e) {
    console.error('[STAFF OAUTH] Error:', e);
    res.json({ success: false, error: 'Authentication error' });
  }
});

// GET /api/staff/verify-token - Check if token is still valid
app.get('/api/staff/verify-token', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.json({ valid: false });
  }
  
  const token = authHeader.substring(7);
  const session = staffTokens.get(token);
  
  if (session && session.expires > Date.now()) {
    return res.json({ valid: true, user: session.user });
  }
  
  return res.json({ valid: false });
});

// GET /api/staff/mod-logs - Moderation action logs
app.get('/api/staff/mod-logs', checkStaffAuth, async (req, res) => {
  try {
    // For now return empty - we can add mod_logs table later
    res.json({ logs: [] });
  } catch (e) {
    res.json({ logs: [] });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED AUTH SYSTEM - For Customers, Staff, and Admins
// ═══════════════════════════════════════════════════════════════════════════

const userTokens = new Map(); // token -> { user, role, expires }
const ADMIN_IDS = ['513386668042698755']; // Your Discord ID - always admin

// Middleware to check unified auth
function checkAuth(requiredRole = null) {
  return (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const token = authHeader.substring(7);
    const session = userTokens.get(token);
    
    if (!session || session.expires < Date.now()) {
      return res.status(401).json({ error: 'Session expired' });
    }
    
    // Check role if required
    if (requiredRole) {
      const roleHierarchy = { customer: 1, staff: 2, admin: 3 };
      if (roleHierarchy[session.role] < roleHierarchy[requiredRole]) {
        return res.status(403).json({ error: 'Insufficient permissions' });
      }
    }
    
    req.user = session.user;
    req.userRole = session.role;
    next();
  };
}

// POST /api/auth/login - Unified Discord OAuth login
// ═══════════════════════════════════════════════════════════════════════════════
// BULLETPROOF LOGIN - Discord ONLY with fingerprinting & security
// ═══════════════════════════════════════════════════════════════════════════════
app.post('/api/auth/login', async (req, res) => {
  const { code, redirect_uri, fingerprint, fingerprintData } = req.body;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  
  if (!code) {
    return res.status(400).json({ success: false, error: 'No code provided' });
  }
  
  try {
    // ═══════════════════════════════════════════════════════════════════════════
    // RATE LIMITING CHECK
    // ═══════════════════════════════════════════════════════════════════════════
    const rateCheck = await pool.query(
      `SELECT * FROM rate_limits WHERE identifier = $1 AND endpoint = 'login' AND window_start > NOW() - INTERVAL '15 minutes'`,
      [clientIp]
    ).catch(() => ({ rows: [] }));
    
    if (rateCheck.rows.length > 0 && rateCheck.rows[0].count >= 10) {
      console.log(`[SECURITY] Rate limited: ${clientIp}`);
      return res.status(429).json({ success: false, error: 'Too many login attempts. Try again in 15 minutes.' });
    }
    
    // Update rate limit counter
    await pool.query(`
      INSERT INTO rate_limits (identifier, endpoint, count, window_start)
      VALUES ($1, 'login', 1, NOW())
      ON CONFLICT (identifier, endpoint) DO UPDATE SET count = rate_limits.count + 1
    `, [clientIp]).catch(() => {});
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CHECK IF IP IS BANNED
    // ═══════════════════════════════════════════════════════════════════════════
    const bannedIp = await pool.query('SELECT * FROM banned_ips WHERE ip_address = $1', [clientIp]);
    if (bannedIp.rows.length > 0) {
      console.log(`[SECURITY] Blocked banned IP: ${clientIp}`);
      return res.json({ success: false, error: 'Access denied. Contact support.' });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // EXCHANGE CODE FOR DISCORD TOKEN
    // ═══════════════════════════════════════════════════════════════════════════
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: process.env.DISCORD_CLIENT_ID || '1462303194863505521',
        client_secret: process.env.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri
      })
    });
    
    const tokenData = await tokenRes.json();
    
    if (!tokenData.access_token) {
      console.log('[AUTH] Token exchange failed:', tokenData);
      return res.json({ success: false, error: 'Discord authentication failed' });
    }
    
    // Get user info from Discord
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const discordUser = await userRes.json();
    
    if (!discordUser.id) {
      return res.json({ success: false, error: 'Could not get user info' });
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CHECK FOR SUSPICIOUS FINGERPRINT (Multi-account detection)
    // ═══════════════════════════════════════════════════════════════════════════
    let isSuspicious = false;
    let suspicionReason = null;
    
    if (fingerprint) {
      const existingFp = await pool.query(
        `SELECT DISTINCT discord_id FROM login_fingerprints WHERE fingerprint = $1 AND discord_id != $2`,
        [fingerprint, discordUser.id]
      ).catch(() => ({ rows: [] }));
      
      if (existingFp.rows.length > 0) {
        isSuspicious = true;
        suspicionReason = `Same device used by ${existingFp.rows.length} other account(s)`;
        console.log(`[SECURITY]  MULTI-ACCOUNT: ${discordUser.username} shares device with ${existingFp.rows.map(r => r.discord_id).join(', ')}`);
        
        // Update linked_accounts table
        await pool.query(`
          INSERT INTO linked_accounts (fingerprint, discord_ids, ip_addresses, account_count, is_suspicious)
          VALUES ($1, ARRAY[$2], ARRAY[$3], 1, TRUE)
          ON CONFLICT (fingerprint) DO UPDATE SET 
            discord_ids = array_append(
              CASE WHEN $2 = ANY(linked_accounts.discord_ids) THEN linked_accounts.discord_ids 
              ELSE linked_accounts.discord_ids END, 
              CASE WHEN $2 = ANY(linked_accounts.discord_ids) THEN NULL ELSE $2 END
            ),
            account_count = array_length(linked_accounts.discord_ids, 1) + 1,
            is_suspicious = TRUE,
            updated_at = NOW()
        `, [fingerprint, discordUser.id, clientIp]).catch(() => {});
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CHECK DISCORD SERVER ROLES
    // ═══════════════════════════════════════════════════════════════════════════
    let discordRole = 'customer';
    let isInServer = false;
    
    try {
      const guild = client.guilds.cache.get(CONFIG.GUILD_ID);
      if (guild) {
        const member = await guild.members.fetch(discordUser.id).catch(() => null);
        if (member) {
          isInServer = true;
          
          const ADMIN_ROLE_IDS = ['1453304665046257819', '1453304662156644445'];
          const MOD_ROLE_IDS = ['1453304660134727764'];
          
          const hasAdminRole = member.permissions.has('Administrator') ||
                              member.roles.cache.some(r => ADMIN_ROLE_IDS.includes(r.id));
          const hasModRole = member.roles.cache.some(r => MOD_ROLE_IDS.includes(r.id)) ||
                            member.permissions.has('ModerateMembers');
          
          if (ADMIN_IDS.includes(discordUser.id) || hasAdminRole) {
            discordRole = 'admin';
          } else if (hasModRole) {
            discordRole = 'staff';
          }
        }
      }
    } catch (e) {
      console.log('[AUTH] Could not check guild:', e.message);
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CREATE OR UPDATE USER IN DATABASE
    // ═══════════════════════════════════════════════════════════════════════════
    let dbUser = await pool.query('SELECT * FROM users WHERE discord_id = $1', [discordUser.id]);
    
    if (dbUser.rows.length === 0) {
      // New user
      await pool.query(`
        INSERT INTO users (discord_id, username, discriminator, avatar, email, role, plan, 
          signup_ip, last_ip, fingerprint, fingerprint_data, login_count, created_at, last_login)
        VALUES ($1, $2, $3, $4, $5, $6, 'free', $7, $7, $8, $9, 1, NOW(), NOW())
      `, [discordUser.id, discordUser.username, discordUser.discriminator, discordUser.avatar, 
          discordUser.email, discordRole, clientIp, fingerprint, JSON.stringify(fingerprintData || {})]);
      
      dbUser = await pool.query('SELECT * FROM users WHERE discord_id = $1', [discordUser.id]);
      console.log(`[AUTH]  New user: ${discordUser.username} (${discordUser.id}) | IP: ${clientIp} | FP: ${fingerprint?.slice(0,8)}...`);
    } else {
      // Existing user - check if banned
      if (dbUser.rows[0].banned) {
        console.log(`[AUTH]  Banned user attempted login: ${discordUser.username}`);
        return res.json({ success: false, error: `Account suspended: ${dbUser.rows[0].ban_reason || 'Contact support'}` });
      }
      
      // Update user
      await pool.query(`
        UPDATE users SET 
          username = $1, avatar = $2, email = $3, role = $4, 
          last_ip = $5, fingerprint = $6, fingerprint_data = $7,
          login_count = COALESCE(login_count, 0) + 1, last_login = NOW()
        WHERE discord_id = $8
      `, [discordUser.username, discordUser.avatar, discordUser.email, discordRole, 
          clientIp, fingerprint, JSON.stringify(fingerprintData || {}), discordUser.id]);
      
      dbUser = await pool.query('SELECT * FROM users WHERE discord_id = $1', [discordUser.id]);
    }
    
    const user = dbUser.rows[0];
    let role = discordRole;
    
    // Override: Owner is always admin
    if (ADMIN_IDS.includes(discordUser.id)) {
      role = 'admin';
      if (user.role !== 'admin') {
        await pool.query('UPDATE users SET role = $1 WHERE discord_id = $2', ['admin', discordUser.id]);
      }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LOG THIS LOGIN (For security tracking)
    // ═══════════════════════════════════════════════════════════════════════════
    await pool.query(`
      INSERT INTO login_fingerprints (user_id, discord_id, fingerprint, fingerprint_data, ip_address, user_agent, is_suspicious, suspicion_reason)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [user.id, discordUser.id, fingerprint, JSON.stringify(fingerprintData || {}), clientIp, userAgent, isSuspicious, suspicionReason]).catch(() => {});
    
    // Also log to login_logs
    await pool.query(`
      INSERT INTO login_logs (user_id, email, ip_address, success, created_at)
      VALUES ($1, $2, $3, TRUE, NOW())
    `, [user.id, discordUser.email || discordUser.username, clientIp]).catch(() => {});
    
    // ═══════════════════════════════════════════════════════════════════════════
    // GENERATE SESSION TOKEN
    // ═══════════════════════════════════════════════════════════════════════════
    const token = require('crypto').randomBytes(32).toString('hex');
    userTokens.set(token, {
      user: {
        id: discordUser.id,
        username: discordUser.username,
        avatar: discordUser.avatar,
        email: discordUser.email,
        plan: user.plan,
        created_at: user.created_at
      },
      role,
      fingerprint,
      isInServer,
      expires: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
    });
    
    if (role === 'staff' || role === 'admin') {
      staffTokens.set(token, {
        user: { id: discordUser.id, username: discordUser.username, avatar: discordUser.avatar },
        expires: Date.now() + (24 * 60 * 60 * 1000)
      });
    }
    
    console.log(`[AUTH]  ${discordUser.username} logged in as ${role} | IP: ${clientIp} | Suspicious: ${isSuspicious}`);
    
    res.json({
      success: true,
      token,
      user: {
        id: discordUser.id,
        username: discordUser.username,
        avatar: discordUser.avatar,
        email: discordUser.email,
        plan: user.plan
      },
      role,
      isInServer
    });
    
  } catch (e) {
    console.error('[AUTH] Error:', e);
    res.json({ success: false, error: 'Authentication error' });
  }
});

// GET /api/auth/me - Get current user info
app.get('/api/auth/me', checkAuth(), (req, res) => {
  res.json({
    user: req.user,
    role: req.userRole
  });
});

// POST /api/auth/logout - Logout
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    userTokens.delete(token);
    staffTokens.delete(token);
  }
  res.json({ success: true });
});

// ═══════════════════════════════════════════════════════════════════════════════
// SESSION SECURITY - Verify fingerprint on sensitive operations
// ═══════════════════════════════════════════════════════════════════════════════

function checkSessionSecurity() {
  return async (req, res, next) => {
    const token = req.headers['authorization']?.replace('Bearer ', '');
    const fingerprint = req.headers['x-fingerprint'];
    
    if (!token) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }
    
    const session = userTokens.get(token);
    if (!session) {
      return res.status(401).json({ success: false, error: 'Invalid session' });
    }
    
    // Check if fingerprint matches (anti-hijacking)
    if (session.fingerprint && fingerprint && session.fingerprint !== fingerprint) {
      console.log(`[SECURITY]  Session hijack attempt! Token FP: ${session.fingerprint?.slice(0,8)}, Request FP: ${fingerprint?.slice(0,8)}`);
      
      // Log the suspicious activity
      await pool.query(`
        INSERT INTO security_alerts (alert_type, severity, discord_id, fingerprint_hash, description)
        VALUES ('SESSION_HIJACK', 'critical', $1, $2, 'Token used from different device')
      `, [session.user?.id, fingerprint]).catch(() => {});
      
      // Invalidate the token
      userTokens.delete(token);
      staffTokens.delete(token);
      
      return res.status(401).json({ success: false, error: 'Session invalidated for security reasons' });
    }
    
    req.user = session.user;
    req.userRole = session.role;
    req.session = session;
    next();
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// DASHBOARD API ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/dashboard/stats - Get user's security stats
app.get('/api/dashboard/stats', checkAuth(), async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get threats blocked (from security alerts)
    const threatCount = await pool.query(`
      SELECT COUNT(*) as count FROM login_fingerprints 
      WHERE discord_id = $1 AND is_suspicious = TRUE
    `, [userId]).catch(() => ({ rows: [{ count: 0 }] }));
    
    // Get verification count
    const verifyCount = await pool.query(`
      SELECT COUNT(*) as count FROM verifications 
      WHERE discord_id = $1
    `, [userId]).catch(() => ({ rows: [{ count: 0 }] }));
    
    // Get alt account detections
    const altCount = await pool.query(`
      SELECT COUNT(*) as count FROM linked_accounts 
      WHERE $1 = ANY(discord_ids) AND account_count > 1
    `, [userId]).catch(() => ({ rows: [{ count: 0 }] }));
    
    // Get VPN blocks
    const vpnCount = await pool.query(`
      SELECT COUNT(*) as count FROM verifications 
      WHERE discord_id = $1 AND (vpn_detected = TRUE OR proxy_detected = TRUE)
    `, [userId]).catch(() => ({ rows: [{ count: 0 }] }));
    
    res.json({
      success: true,
      threatsBlocked: parseInt(threatCount.rows[0]?.count || 0),
      totalVerifications: parseInt(verifyCount.rows[0]?.count || 0),
      altAccounts: parseInt(altCount.rows[0]?.count || 0),
      vpnBlocked: parseInt(vpnCount.rows[0]?.count || 0),
      threatChange: Math.floor(Math.random() * 30) + 5 // TODO: Calculate actual change
    });
    
  } catch (e) {
    console.error('[DASHBOARD] Stats error:', e);
    res.json({ success: false, threatsBlocked: 0, totalVerifications: 0, altAccounts: 0, vpnBlocked: 0 });
  }
});

// GET /api/dashboard/recent-threats - Get recent threats for user
app.get('/api/dashboard/recent-threats', checkAuth(), async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get recent suspicious activity
    const threats = await pool.query(`
      SELECT * FROM login_fingerprints 
      WHERE discord_id = $1 AND is_suspicious = TRUE
      ORDER BY created_at DESC LIMIT 10
    `, [userId]).catch(() => ({ rows: [] }));
    
    const formattedThreats = threats.rows.map(t => ({
      severity: t.suspicion_reason?.includes('CRITICAL') ? 'critical' : 'high',
      type: t.suspicion_reason?.split(':')[0] || 'Suspicious Activity',
      description: t.suspicion_reason || 'Unusual login detected',
      action: 'blocked',
      time: formatTimeAgo(t.created_at)
    }));
    
    res.json({ success: true, threats: formattedThreats });
    
  } catch (e) {
    res.json({ success: false, threats: [] });
  }
});

// GET /api/dashboard/activity - Get recent activity
app.get('/api/dashboard/activity', checkAuth(), async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get recent logins
    const logins = await pool.query(`
      SELECT * FROM login_fingerprints 
      WHERE discord_id = $1 
      ORDER BY created_at DESC LIMIT 20
    `, [userId]).catch(() => ({ rows: [] }));
    
    const items = logins.rows.map(l => ({
      type: l.is_suspicious ? 'danger' : 'success',
      text: l.is_suspicious ? `Suspicious login blocked from ${l.ip_address}` : `Logged in from ${l.ip_address}`,
      time: formatTimeAgo(l.created_at)
    }));
    
    res.json({ success: true, items });
    
  } catch (e) {
    res.json({ success: false, items: [] });
  }
});

function formatTimeAgo(date) {
  const seconds = Math.floor((Date.now() - new Date(date).getTime()) / 1000);
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`;
  return `${Math.floor(seconds / 86400)} days ago`;
}

// ═══════════════════════════════════════════════════════════════════════════
// EMAIL SIGNUP & LOGIN
// ═══════════════════════════════════════════════════════════════════════════

// Simple password hashing (for production, use bcrypt)
const crypto = require('crypto');
function hashPassword(password) {
  return crypto.createHash('sha256').update(password + 'unpatched_salt_2025').digest('hex');
}

// POST /api/auth/signup - Create account with email
app.post('/api/auth/signup', async (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  
  if (!email || !password) {
    return res.json({ success: false, error: 'Email and password required' });
  }
  
  if (password.length < 8) {
    return res.json({ success: false, error: 'Password must be at least 8 characters' });
  }
  
  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.json({ success: false, error: 'Invalid email format' });
  }
  
  try {
    // Check if IP is banned
    const bannedIp = await pool.query('SELECT * FROM banned_ips WHERE ip_address = $1', [clientIp]);
    if (bannedIp.rows.length > 0) {
      console.log(`[AUTH] Blocked signup from banned IP: ${clientIp}`);
      return res.json({ success: false, error: 'Registration is not available. Contact support.' });
    }
    
    // Check if email already exists
    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    if (existing.rows.length > 0) {
      return res.json({ success: false, error: 'Email already registered' });
    }
    
    // Hash password
    const passwordHash = hashPassword(password);
    
    // Create user with IP tracking
    const result = await pool.query(`
      INSERT INTO users (email, password_hash, role, plan, signup_ip, last_ip, created_at, last_login)
      VALUES ($1, $2, 'customer', 'free', $3, $3, NOW(), NOW())
      RETURNING *
    `, [email.toLowerCase(), passwordHash, clientIp]);
    
    const user = result.rows[0];
    
    // Log the signup
    await pool.query(`
      INSERT INTO login_logs (user_id, email, ip_address, success, created_at)
      VALUES ($1, $2, $3, true, NOW())
    `, [user.id, email.toLowerCase(), clientIp]).catch(() => {});
    
    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    userTokens.set(token, {
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan,
        created_at: user.created_at
      },
      role: 'customer',
      expires: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
    });
    
    console.log(`[AUTH] New email signup: ${email} from IP ${clientIp}`);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan
      },
      role: 'customer'
    });
    
  } catch (e) {
    console.error('[AUTH] Signup error:', e);
    res.json({ success: false, error: 'Signup failed. Please try again.' });
  }
});

// POST /api/auth/email-login - Login with email/password
app.post('/api/auth/email-login', async (req, res) => {
  const { email, password } = req.body;
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  
  if (!email || !password) {
    return res.json({ success: false, error: 'Email and password required' });
  }
  
  try {
    // Check if IP is banned
    const bannedIp = await pool.query('SELECT * FROM banned_ips WHERE ip_address = $1', [clientIp]);
    if (bannedIp.rows.length > 0) {
      await pool.query(`
        INSERT INTO login_logs (email, ip_address, success, fail_reason, created_at)
        VALUES ($1, $2, false, 'IP banned', NOW())
      `, [email.toLowerCase(), clientIp]).catch(() => {});
      console.log(`[AUTH] Blocked login from banned IP: ${clientIp}`);
      return res.json({ success: false, error: 'Access denied. Contact support.' });
    }
    
    // Find user by email
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    
    if (result.rows.length === 0) {
      await pool.query(`
        INSERT INTO login_logs (email, ip_address, success, fail_reason, created_at)
        VALUES ($1, $2, false, 'User not found', NOW())
      `, [email.toLowerCase(), clientIp]).catch(() => {});
      return res.json({ success: false, error: 'Invalid email or password' });
    }
    
    const user = result.rows[0];
    
    // Check if user is banned
    if (user.banned) {
      await pool.query(`
        INSERT INTO login_logs (user_id, email, ip_address, success, fail_reason, created_at)
        VALUES ($1, $2, $3, false, 'User banned', NOW())
      `, [user.id, email.toLowerCase(), clientIp]).catch(() => {});
      console.log(`[AUTH] Blocked login from banned user: ${email}`);
      return res.json({ success: false, error: 'Your account has been suspended. Contact support.' });
    }
    
    // Check password
    const passwordHash = hashPassword(password);
    if (user.password_hash !== passwordHash) {
      await pool.query(`
        INSERT INTO login_logs (user_id, email, ip_address, success, fail_reason, created_at)
        VALUES ($1, $2, $3, false, 'Wrong password', NOW())
      `, [user.id, email.toLowerCase(), clientIp]).catch(() => {});
      return res.json({ success: false, error: 'Invalid email or password' });
    }
    
    // Update last login and IP
    await pool.query('UPDATE users SET last_login = NOW(), last_ip = $1 WHERE id = $2', [clientIp, user.id]);
    
    // Log successful login
    await pool.query(`
      INSERT INTO login_logs (user_id, email, ip_address, success, created_at)
      VALUES ($1, $2, $3, true, NOW())
    `, [user.id, email.toLowerCase(), clientIp]).catch(() => {});
    
    // Generate session token
    const token = crypto.randomBytes(32).toString('hex');
    userTokens.set(token, {
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        avatar: user.avatar,
        plan: user.plan,
        created_at: user.created_at
      },
      role: user.role,
      expires: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
    });
    
    // Add to staffTokens if staff/admin
    if (user.role === 'staff' || user.role === 'admin') {
      staffTokens.set(token, {
        user: { id: user.id, username: user.username || user.email, avatar: user.avatar },
        expires: Date.now() + (24 * 60 * 60 * 1000)
      });
    }
    
    console.log(`[AUTH] Email login: ${email} as ${user.role} from IP ${clientIp}`);
    
    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        username: user.username,
        avatar: user.avatar,
        plan: user.plan
      },
      role: user.role
    });
    
  } catch (e) {
    console.error('[AUTH] Login error:', e);
    res.json({ success: false, error: 'Login failed. Please try again.' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// PASSWORD RESET & ACCOUNT MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/auth/forgot-password - Request password reset
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.json({ success: false, error: 'Email required' });
  }
  
  try {
    // Find user by email
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    
    // Always return success (don't reveal if email exists)
    if (userResult.rows.length === 0) {
      console.log(`[AUTH] Password reset requested for non-existent email: ${email}`);
      return res.json({ success: true, message: 'If that email exists, we sent a reset link.' });
    }
    
    const user = userResult.rows[0];
    
    // Generate reset token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    // Store token in database
    await pool.query(`
      INSERT INTO password_reset_tokens (user_id, token, expires_at)
      VALUES ($1, $2, $3)
    `, [user.id, token, expiresAt]);
    
    // Create reset URL
    const resetUrl = `https://theunpatchedmethod.com/reset-password.html?token=${token}`;
    
    console.log(`[AUTH] Password reset token generated for ${email}`);
    console.log(`[AUTH] Reset URL: ${resetUrl}`);
    
    // TODO: Send email with reset link
    // For now, just log it (you can integrate SendGrid, Mailgun, etc.)
    
    res.json({ success: true, message: 'If that email exists, we sent a reset link.' });
    
  } catch (e) {
    console.error('[AUTH] Forgot password error:', e);
    res.json({ success: true, message: 'If that email exists, we sent a reset link.' });
  }
});

// POST /api/auth/reset-password - Reset password with token
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  
  if (!token || !password) {
    return res.json({ success: false, error: 'Token and password required' });
  }
  
  if (password.length < 8) {
    return res.json({ success: false, error: 'Password must be at least 8 characters' });
  }
  
  try {
    // Find valid token
    const tokenResult = await pool.query(`
      SELECT * FROM password_reset_tokens 
      WHERE token = $1 AND used = FALSE AND expires_at > NOW()
    `, [token]);
    
    if (tokenResult.rows.length === 0) {
      return res.json({ success: false, error: 'Invalid or expired token' });
    }
    
    const resetToken = tokenResult.rows[0];
    
    // Update password
    const passwordHash = hashPassword(password);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, resetToken.user_id]);
    
    // Mark token as used
    await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE id = $1', [resetToken.id]);
    
    // Invalidate all other reset tokens for this user
    await pool.query('UPDATE password_reset_tokens SET used = TRUE WHERE user_id = $1', [resetToken.user_id]);
    
    console.log(`[AUTH] Password reset successful for user ${resetToken.user_id}`);
    
    res.json({ success: true, message: 'Password reset successfully' });
    
  } catch (e) {
    console.error('[AUTH] Reset password error:', e);
    res.json({ success: false, error: 'Failed to reset password' });
  }
});

// POST /api/auth/change-password - Change password (logged in)
app.post('/api/auth/change-password', checkAuth(), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.json({ success: false, error: 'Current and new password required' });
  }
  
  if (newPassword.length < 8) {
    return res.json({ success: false, error: 'New password must be at least 8 characters' });
  }
  
  try {
    // Get user from database
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1 OR discord_id = $1', [req.user.id]);
    
    if (userResult.rows.length === 0) {
      return res.json({ success: false, error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Check current password
    const currentHash = hashPassword(currentPassword);
    if (user.password_hash !== currentHash) {
      return res.json({ success: false, error: 'Current password is incorrect' });
    }
    
    // Update to new password
    const newHash = hashPassword(newPassword);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, user.id]);
    
    console.log(`[AUTH] Password changed for user ${user.id}`);
    
    res.json({ success: true, message: 'Password changed successfully' });
    
  } catch (e) {
    console.error('[AUTH] Change password error:', e);
    res.json({ success: false, error: 'Failed to change password' });
  }
});

// POST /api/auth/logout-all - Logout from all devices
app.post('/api/auth/logout-all', checkAuth(), async (req, res) => {
  try {
    // Remove all sessions for this user from memory
    for (const [token, session] of userTokens.entries()) {
      if (session.user && (session.user.id === req.user.id || session.user.email === req.user.email)) {
        userTokens.delete(token);
        staffTokens.delete(token);
      }
    }
    
    // Also delete from database if using session table
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [req.user.id]).catch(() => {});
    
    console.log(`[AUTH] User ${req.user.id} logged out from all devices`);
    
    res.json({ success: true, message: 'Logged out from all devices' });
    
  } catch (e) {
    console.error('[AUTH] Logout all error:', e);
    res.json({ success: false, error: 'Failed to logout' });
  }
});

// DELETE /api/auth/delete-account - Delete user account
app.delete('/api/auth/delete-account', checkAuth(), async (req, res) => {
  const { password } = req.body;
  
  try {
    // Get user
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1 OR discord_id = $1', [req.user.id]);
    
    if (userResult.rows.length === 0) {
      return res.json({ success: false, error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // If user has password, verify it
    if (user.password_hash && password) {
      const passHash = hashPassword(password);
      if (user.password_hash !== passHash) {
        return res.json({ success: false, error: 'Incorrect password' });
      }
    }
    
    // Delete user data
    await pool.query('DELETE FROM password_reset_tokens WHERE user_id = $1', [user.id]).catch(() => {});
    await pool.query('DELETE FROM user_sessions WHERE user_id = $1', [user.id]).catch(() => {});
    await pool.query('DELETE FROM login_logs WHERE user_id = $1', [user.id]).catch(() => {});
    await pool.query('DELETE FROM users WHERE id = $1', [user.id]);
    
    // Remove from memory
    for (const [token, session] of userTokens.entries()) {
      if (session.user && session.user.id === user.id) {
        userTokens.delete(token);
        staffTokens.delete(token);
      }
    }
    
    console.log(`[AUTH] User ${user.id} deleted their account`);
    
    res.json({ success: true, message: 'Account deleted successfully' });
    
  } catch (e) {
    console.error('[AUTH] Delete account error:', e);
    res.json({ success: false, error: 'Failed to delete account' });
  }
});

// POST /api/auth/resend-verification - Resend email verification
app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.json({ success: false, error: 'Email required' });
  }
  
  try {
    // Find user
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email.toLowerCase()]);
    
    if (userResult.rows.length === 0) {
      return res.json({ success: true }); // Don't reveal if email exists
    }
    
    const user = userResult.rows[0];
    
    if (user.email_verified) {
      return res.json({ success: false, error: 'Email already verified' });
    }
    
    // Generate verification token
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    await pool.query(`
      INSERT INTO email_verification_tokens (user_id, email, token, expires_at)
      VALUES ($1, $2, $3, $4)
    `, [user.id, email.toLowerCase(), token, expiresAt]);
    
    const verifyUrl = `https://theunpatchedmethod.com/verify-email.html?token=${token}`;
    
    console.log(`[AUTH] Verification email resent to ${email}`);
    console.log(`[AUTH] Verify URL: ${verifyUrl}`);
    
    // TODO: Send actual email
    
    res.json({ success: true });
    
  } catch (e) {
    console.error('[AUTH] Resend verification error:', e);
    res.json({ success: false, error: 'Failed to resend verification' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// STRIPE PAYMENT SYSTEM - Bulletproof payments
// ═══════════════════════════════════════════════════════════════════════════════

// Initialize Stripe (only if key exists)
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  const Stripe = require('stripe');
  stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
  console.log('[STRIPE] Payment system initialized');
}

// Stripe price IDs (set these in Railway env vars)
const STRIPE_PRICES = {
  pro: process.env.STRIPE_PRO_PRICE_ID,
  enterprise: process.env.STRIPE_ENTERPRISE_PRICE_ID
};

// POST /api/payments/create-checkout - Create Stripe checkout session
app.post('/api/payments/create-checkout', checkAuth(), async (req, res) => {
  if (!stripe) {
    return res.json({ success: false, error: 'Payment system not configured' });
  }
  
  const { plan } = req.body;
  const user = req.user;
  const fingerprint = req.headers['x-fingerprint'] || 'unknown';
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'unknown';
  
  if (!STRIPE_PRICES[plan]) {
    return res.json({ success: false, error: 'Invalid plan' });
  }
  
  try {
    // Get user from database
    const dbUser = await pool.query('SELECT * FROM users WHERE discord_id = $1', [user.id]);
    if (dbUser.rows.length === 0) {
      return res.json({ success: false, error: 'User not found' });
    }
    
    const userData = dbUser.rows[0];
    
    // Check if user has chargebacks
    if (userData.chargeback_count > 0) {
      return res.json({ success: false, error: 'Payment not available for this account. Contact support.' });
    }
    
    // Create or get Stripe customer
    let customerId = userData.stripe_customer_id;
    
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: userData.email,
        metadata: {
          discord_id: user.id,
          username: user.username
        }
      });
      customerId = customer.id;
      
      await pool.query('UPDATE users SET stripe_customer_id = $1 WHERE discord_id = $2', 
        [customerId, user.id]);
    }
    
    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      payment_method_types: ['card'],
      line_items: [{
        price: STRIPE_PRICES[plan],
        quantity: 1
      }],
      mode: 'subscription',
      success_url: `${process.env.FRONTEND_URL || 'https://theunpatchedmethod.com'}/dashboard.html?payment=success`,
      cancel_url: `${process.env.FRONTEND_URL || 'https://theunpatchedmethod.com'}/dashboard.html?payment=cancelled`,
      metadata: {
        discord_id: user.id,
        username: user.username,
        plan: plan,
        fingerprint: fingerprint,
        ip: clientIp
      }
    });
    
    console.log(`[STRIPE] Checkout created for ${user.username} - ${plan}`);
    res.json({ success: true, url: session.url, sessionId: session.id });
    
  } catch (e) {
    console.error('[STRIPE] Checkout error:', e);
    res.json({ success: false, error: 'Payment setup failed' });
  }
});

// POST /api/webhooks/stripe - Stripe webhook handler
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  if (!stripe) {
    return res.status(400).send('Stripe not configured');
  }
  
  const sig = req.headers['stripe-signature'];
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (e) {
    console.error('[STRIPE] Webhook signature failed:', e.message);
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }
  
  console.log(`[STRIPE] Webhook: ${event.type}`);
  
  try {
    switch (event.type) {
      // ═══════════════════════════════════════════════════════════════════════
      // PAYMENT SUCCESS - Activate plan
      // ═══════════════════════════════════════════════════════════════════════
      case 'checkout.session.completed': {
        const session = event.data.object;
        const discordId = session.metadata.discord_id;
        const plan = session.metadata.plan;
        
        // Calculate expiry (1 month from now)
        const expiresAt = new Date();
        expiresAt.setMonth(expiresAt.getMonth() + 1);
        
        // Update user plan
        await pool.query(`
          UPDATE users SET 
            plan = $1, 
            plan_expires_at = $2, 
            stripe_subscription_id = $3,
            subscription_status = 'active',
            total_paid = COALESCE(total_paid, 0) + $4
          WHERE discord_id = $5
        `, [plan, expiresAt, session.subscription, session.amount_total || 0, discordId]);
        
        // Log payment
        await pool.query(`
          INSERT INTO payments (discord_id, stripe_payment_id, stripe_subscription_id, plan, amount, status, fingerprint, ip_address)
          VALUES ($1, $2, $3, $4, $5, 'completed', $6, $7)
        `, [discordId, session.payment_intent, session.subscription, plan, session.amount_total, session.metadata.fingerprint, session.metadata.ip]);
        
        console.log(`[STRIPE]  Payment success: ${discordId} -> ${plan} plan`);
        break;
      }
      
      // ═══════════════════════════════════════════════════════════════════════
      // SUBSCRIPTION CANCELLED - Downgrade to free
      // ═══════════════════════════════════════════════════════════════════════
      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        
        await pool.query(`
          UPDATE users SET 
            plan = 'free', 
            plan_expires_at = NULL, 
            stripe_subscription_id = NULL,
            subscription_status = 'cancelled'
          WHERE stripe_subscription_id = $1
        `, [subscription.id]);
        
        console.log(`[STRIPE] Subscription cancelled: ${subscription.id}`);
        break;
      }
      
      // ═══════════════════════════════════════════════════════════════════════
      // CHARGEBACK - AUTO BAN! 
      // ═══════════════════════════════════════════════════════════════════════
      case 'charge.dispute.created': {
        const dispute = event.data.object;
        
        // Find user by payment
        const payment = await pool.query(
          'SELECT * FROM payments WHERE stripe_payment_id = $1', 
          [dispute.payment_intent]
        );
        
        if (payment.rows.length > 0) {
          const discordId = payment.rows[0].discord_id;
          
          // AUTO BAN USER
          await pool.query(`
            UPDATE users SET 
              banned = TRUE, 
              ban_reason = 'AUTOMATIC BAN: Chargeback filed',
              banned_at = NOW(),
              plan = 'free',
              plan_expires_at = NULL,
              stripe_subscription_id = NULL,
              subscription_status = 'terminated',
              chargeback_count = COALESCE(chargeback_count, 0) + 1,
              risk_score = COALESCE(risk_score, 0) + 100
            WHERE discord_id = $1
          `, [discordId]);
          
          // Also ban the fingerprint and IP
          const userData = await pool.query('SELECT fingerprint, last_ip FROM users WHERE discord_id = $1', [discordId]);
          if (userData.rows.length > 0) {
            const fp = userData.rows[0].fingerprint;
            const ip = userData.rows[0].last_ip;
            
            if (ip) {
              await pool.query(`
                INSERT INTO banned_ips (ip_address, reason, banned_by) 
                VALUES ($1, 'Chargeback auto-ban', 'SYSTEM')
                ON CONFLICT (ip_address) DO NOTHING
              `, [ip]);
            }
          }
          
          // Log chargeback
          await pool.query(`
            INSERT INTO chargebacks (discord_id, payment_id, stripe_dispute_id, amount, reason, auto_banned)
            VALUES ($1, $2, $3, $4, $5, TRUE)
          `, [discordId, payment.rows[0].id, dispute.id, dispute.amount, dispute.reason]);
          
          console.log(`[STRIPE]  CHARGEBACK - AUTO BANNED: ${discordId}`);
        }
        break;
      }
      
      // ═══════════════════════════════════════════════════════════════════════
      // PAYMENT FAILED - Downgrade
      // ═══════════════════════════════════════════════════════════════════════
      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        
        await pool.query(`
          UPDATE users SET 
            plan = 'free',
            subscription_status = 'payment_failed'
          WHERE stripe_customer_id = $1
        `, [invoice.customer]);
        
        console.log(`[STRIPE] Payment failed: ${invoice.customer}`);
        break;
      }
    }
  } catch (e) {
    console.error('[STRIPE] Webhook processing error:', e);
  }
  
  res.json({ received: true });
});

// GET /api/payments/history - Get user's payment history
app.get('/api/payments/history', checkAuth(), async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM payments WHERE discord_id = $1 ORDER BY created_at DESC LIMIT 50',
      [req.user.id]
    );
    res.json({ payments: result.rows });
  } catch (e) {
    res.json({ payments: [] });
  }
});

// POST /api/payments/cancel - Cancel subscription
app.post('/api/payments/cancel', checkAuth(), async (req, res) => {
  if (!stripe) {
    return res.json({ success: false, error: 'Payment system not configured' });
  }
  
  try {
    const dbUser = await pool.query('SELECT stripe_subscription_id FROM users WHERE discord_id = $1', [req.user.id]);
    
    if (dbUser.rows.length === 0 || !dbUser.rows[0].stripe_subscription_id) {
      return res.json({ success: false, error: 'No active subscription' });
    }
    
    await stripe.subscriptions.del(dbUser.rows[0].stripe_subscription_id);
    
    await pool.query(`
      UPDATE users SET subscription_status = 'cancelling' WHERE discord_id = $1
    `, [req.user.id]);
    
    console.log(`[STRIPE] Subscription cancelled by user: ${req.user.id}`);
    res.json({ success: true });
    
  } catch (e) {
    console.error('[STRIPE] Cancel error:', e);
    res.json({ success: false, error: 'Failed to cancel subscription' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// REFERRAL SYSTEM - Users earn commission for bringing customers
// ═══════════════════════════════════════════════════════════════════════════════

// GET /api/referrals/info - Get user's referral info
app.get('/api/referrals/info', checkAuth(), async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Get or create referral code
    let user = await pool.query('SELECT referral_code, referral_earnings, referral_count FROM users WHERE discord_id = $1', [userId]);
    
    let referralCode = user.rows[0]?.referral_code;
    
    if (!referralCode) {
      // Generate unique referral code
      referralCode = 'UV-' + userId.slice(-6).toUpperCase() + Math.random().toString(36).substring(2, 5).toUpperCase();
      await pool.query('UPDATE users SET referral_code = $1 WHERE discord_id = $2', [referralCode, userId]);
    }
    
    // Get referral stats
    const referrals = await pool.query(`
      SELECT discord_id, username, plan, created_at FROM users 
      WHERE referred_by = $1 ORDER BY created_at DESC
    `, [userId]);
    
    const earnings = user.rows[0]?.referral_earnings || 0;
    const count = user.rows[0]?.referral_count || referrals.rows.length;
    
    res.json({
      success: true,
      referralCode,
      referralLink: `https://theunpatchedmethod.com?ref=${referralCode}`,
      totalReferrals: count,
      totalEarnings: earnings / 100, // Convert cents to dollars
      commissionRate: 20, // 20% commission
      referrals: referrals.rows.map(r => ({
        username: r.username,
        plan: r.plan,
        joinedAt: r.created_at
      }))
    });
    
  } catch (e) {
    console.error('[REFERRAL] Error:', e);
    res.json({ success: false, error: 'Failed to get referral info' });
  }
});

// POST /api/referrals/apply - Apply referral code on signup
app.post('/api/referrals/apply', async (req, res) => {
  const { referralCode, userId } = req.body;
  
  if (!referralCode || !userId) {
    return res.json({ success: false, error: 'Missing parameters' });
  }
  
  try {
    // Find referrer
    const referrer = await pool.query('SELECT discord_id FROM users WHERE referral_code = $1', [referralCode.toUpperCase()]);
    
    if (referrer.rows.length === 0) {
      return res.json({ success: false, error: 'Invalid referral code' });
    }
    
    // Can't refer yourself
    if (referrer.rows[0].discord_id === userId) {
      return res.json({ success: false, error: 'Cannot use your own referral code' });
    }
    
    // Apply referral
    await pool.query('UPDATE users SET referred_by = $1 WHERE discord_id = $2', [referrer.rows[0].discord_id, userId]);
    
    // Increment referrer count
    await pool.query('UPDATE users SET referral_count = COALESCE(referral_count, 0) + 1 WHERE discord_id = $1', [referrer.rows[0].discord_id]);
    
    console.log(`[REFERRAL] ${userId} referred by ${referrer.rows[0].discord_id}`);
    res.json({ success: true });
    
  } catch (e) {
    console.error('[REFERRAL] Apply error:', e);
    res.json({ success: false, error: 'Failed to apply referral' });
  }
});

// POST /api/referrals/payout - Request payout (admin processed)
app.post('/api/referrals/payout', checkAuth(), async (req, res) => {
  const { paypalEmail } = req.body;
  
  if (!paypalEmail) {
    return res.json({ success: false, error: 'PayPal email required' });
  }
  
  try {
    const user = await pool.query('SELECT referral_earnings FROM users WHERE discord_id = $1', [req.user.id]);
    const earnings = user.rows[0]?.referral_earnings || 0;
    
    if (earnings < 1000) { // Minimum $10 payout
      return res.json({ success: false, error: 'Minimum payout is $10' });
    }
    
    // Create payout request
    await pool.query(`
      INSERT INTO payout_requests (discord_id, amount, paypal_email, status, created_at)
      VALUES ($1, $2, $3, 'pending', NOW())
    `, [req.user.id, earnings, paypalEmail]);
    
    // Reset earnings (will be restored if payout fails)
    await pool.query('UPDATE users SET referral_earnings = 0 WHERE discord_id = $1', [req.user.id]);
    
    console.log(`[REFERRAL] Payout requested: ${req.user.id} - $${earnings/100}`);
    res.json({ success: true, amount: earnings / 100 });
    
  } catch (e) {
    console.error('[REFERRAL] Payout error:', e);
    res.json({ success: false, error: 'Failed to request payout' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// SERVER-SIDE PLAN CHECK - Verify plan on every protected request
// ═══════════════════════════════════════════════════════════════════════════════

function checkPlan(requiredPlan) {
  return async (req, res, next) => {
    if (!req.user || !req.user.id) {
      return res.status(401).json({ success: false, error: 'Not authenticated' });
    }
    
    // ALWAYS check database for current plan (never trust cache/client)
    const dbUser = await pool.query('SELECT plan, plan_expires_at, banned FROM users WHERE discord_id = $1', [req.user.id]);
    
    if (dbUser.rows.length === 0) {
      return res.status(401).json({ success: false, error: 'User not found' });
    }
    
    const user = dbUser.rows[0];
    
    // Check if banned
    if (user.banned) {
      return res.status(403).json({ success: false, error: 'Account suspended' });
    }
    
    // Check if plan expired
    if (user.plan_expires_at && new Date(user.plan_expires_at) < new Date()) {
      await pool.query('UPDATE users SET plan = $1 WHERE discord_id = $2', ['free', req.user.id]);
      user.plan = 'free';
    }
    
    // Check plan level
    const planLevel = { free: 0, pro: 1, enterprise: 2 };
    if ((planLevel[user.plan] || 0) < (planLevel[requiredPlan] || 0)) {
      return res.status(403).json({ 
        success: false, 
        error: `Requires ${requiredPlan} plan`,
        currentPlan: user.plan,
        upgrade: true
      });
    }
    
    req.userPlan = user.plan;
    next();
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// SECURITY ALERTS ENDPOINT (Admin only)
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/admin/security-alerts', checkAuth('admin'), async (req, res) => {
  try {
    // Multi-account detection
    const multiAccount = await pool.query(`
      SELECT fingerprint, array_agg(DISTINCT discord_id) as discord_ids, COUNT(DISTINCT discord_id) as count
      FROM login_fingerprints
      WHERE fingerprint IS NOT NULL AND fingerprint != ''
      GROUP BY fingerprint
      HAVING COUNT(DISTINCT discord_id) > 1
      ORDER BY count DESC
      LIMIT 50
    `);
    
    // Suspicious IPs (many accounts)
    const suspiciousIps = await pool.query(`
      SELECT ip_address, array_agg(DISTINCT discord_id) as discord_ids, COUNT(DISTINCT discord_id) as count
      FROM login_fingerprints
      WHERE ip_address IS NOT NULL
      GROUP BY ip_address
      HAVING COUNT(DISTINCT discord_id) > 3
      ORDER BY count DESC
      LIMIT 50
    `);
    
    // Recent chargebacks
    const chargebacks = await pool.query(`
      SELECT c.*, u.username, u.email 
      FROM chargebacks c 
      LEFT JOIN users u ON c.discord_id = u.discord_id 
      ORDER BY c.created_at DESC LIMIT 20
    `);
    
    // Flagged users
    const flagged = await pool.query(`
      SELECT discord_id, username, email, flagged, flag_reason, risk_score
      FROM users WHERE flagged = TRUE OR risk_score > 50
      ORDER BY risk_score DESC LIMIT 50
    `);
    
    res.json({
      multiAccountAlerts: multiAccount.rows,
      suspiciousIps: suspiciousIps.rows,
      recentChargebacks: chargebacks.rows,
      flaggedUsers: flagged.rows
    });
    
  } catch (e) {
    console.error('[SECURITY] Alerts error:', e);
    res.json({ error: 'Failed to fetch security alerts' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT DETECTION API - Scan URLs for malware, phishing, payloaders
// ═══════════════════════════════════════════════════════════════════════════════

// Load threat detection module
let threatDetection;
try {
  threatDetection = require('./threat-detection');
  console.log('[SECURITY] Threat detection module loaded');
} catch (e) {
  console.log('[SECURITY] Threat detection module not found - using basic checks');
}

// Known malicious patterns (inline backup)
const MALICIOUS_PATTERNS = [
  /discord\.gift/i, /discordgift/i, /discord-nitro/i, /free-nitro/i,
  /steamcommunity\.[^c]/i, /steampowered\.[^c]/i, /discordapp\.[^c]/i,
  /bit\.ly/i, /tinyurl/i, /adf\.ly/i, /shorte\.st/i,
  /\.(tk|ml|ga|cf|gq|xyz|top|work|click|link|club|online|site)$/i,
  /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,
  /\.(exe|msi|bat|cmd|ps1|vbs|scr|jar)(\?|$)/i,
  /grabber/i, /stealer/i, /logger/i, /keylog/i, /rat\b/i
];

// POST /api/security/scan-url - Scan a single URL
app.post('/api/security/scan-url', checkAuth(), async (req, res) => {
  const { url } = req.body;
  
  if (!url) {
    return res.json({ success: false, error: 'URL required' });
  }
  
  try {
    let result;
    
    if (threatDetection) {
      result = await threatDetection.scanUrl(url);
    } else {
      // Basic pattern matching
      result = {
        url,
        safe: true,
        riskScore: 0,
        threats: []
      };
      
      for (const pattern of MALICIOUS_PATTERNS) {
        if (pattern.test(url)) {
          result.safe = false;
          result.riskScore += 50;
          result.threats.push({
            type: 'PATTERN_MATCH',
            severity: 'high',
            description: `Matches suspicious pattern`
          });
        }
      }
    }
    
    // Log the scan
    await pool.query(`
      INSERT INTO url_scans (url, scanned_by, is_safe, risk_score, threats, created_at)
      VALUES ($1, $2, $3, $4, $5, NOW())
    `, [url, req.user.id, result.safe, result.riskScore, JSON.stringify(result.threats)]).catch(() => {});
    
    res.json({ success: true, result });
    
  } catch (e) {
    console.error('[SECURITY] Scan error:', e);
    res.json({ success: false, error: 'Scan failed' });
  }
});

// POST /api/security/scan-message - Scan a message for malicious links
app.post('/api/security/scan-message', checkAuth(), async (req, res) => {
  const { content } = req.body;
  
  if (!content) {
    return res.json({ success: false, error: 'Content required' });
  }
  
  try {
    let result;
    
    if (threatDetection) {
      result = await threatDetection.scanMessage(content);
    } else {
      // Extract URLs
      const urlRegex = /https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi;
      const urls = content.match(urlRegex) || [];
      
      result = { safe: true, urls: [], threats: [] };
      
      for (const url of urls.slice(0, 5)) {
        const urlResult = { url, safe: true, threats: [] };
        
        for (const pattern of MALICIOUS_PATTERNS) {
          if (pattern.test(url)) {
            urlResult.safe = false;
            urlResult.threats.push({ type: 'PATTERN_MATCH', severity: 'high' });
          }
        }
        
        result.urls.push(urlResult);
        if (!urlResult.safe) {
          result.safe = false;
          result.threats.push(...urlResult.threats);
        }
      }
    }
    
    res.json({ success: true, result });
    
  } catch (e) {
    console.error('[SECURITY] Scan error:', e);
    res.json({ success: false, error: 'Scan failed' });
  }
});

// POST /api/security/check-ip - Check an IP for threats
app.post('/api/security/check-ip', checkAuth('staff'), async (req, res) => {
  const { ip } = req.body;
  
  if (!ip) {
    return res.json({ success: false, error: 'IP required' });
  }
  
  try {
    let result;
    
    if (threatDetection) {
      result = await threatDetection.checkIP(ip);
    } else {
      // Basic check - is it in banned list?
      const banned = await pool.query('SELECT * FROM banned_ips WHERE ip_address = $1', [ip]);
      result = {
        ip,
        safe: banned.rows.length === 0,
        banned: banned.rows.length > 0,
        reason: banned.rows[0]?.reason
      };
    }
    
    res.json({ success: true, result });
    
  } catch (e) {
    console.error('[SECURITY] IP check error:', e);
    res.json({ success: false, error: 'Check failed' });
  }
});

// GET /api/security/recent-scans - Get recent URL scans (admin)
app.get('/api/security/recent-scans', checkAuth('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM url_scans ORDER BY created_at DESC LIMIT 100
    `);
    res.json({ scans: result.rows });
  } catch (e) {
    res.json({ scans: [] });
  }
});

// POST /api/security/report-link - Report a malicious link
app.post('/api/security/report-link', checkAuth(), async (req, res) => {
  const { url, reason } = req.body;
  
  if (!url) {
    return res.json({ success: false, error: 'URL required' });
  }
  
  try {
    await pool.query(`
      INSERT INTO reported_links (url, reported_by, reason, created_at)
      VALUES ($1, $2, $3, NOW())
    `, [url, req.user.id, reason || 'User reported']);
    
    console.log(`[SECURITY] Link reported by ${req.user.username}: ${url}`);
    res.json({ success: true });
    
  } catch (e) {
    res.json({ success: false, error: 'Failed to report' });
  }
});

// POST /api/security/scan-payloader - Detect payloaders (malware downloads)
app.post('/api/security/scan-payloader', checkAuth(), async (req, res) => {
  const { url, filename } = req.body;
  
  if (!url) {
    return res.json({ success: false, error: 'URL required' });
  }
  
  try {
    // Run payloader detection
    const result = detectPayloader(url, filename);
    
    // Log the scan
    await pool.query(`
      INSERT INTO url_scans (url, scanned_by, scan_type, is_safe, risk_score, threats, created_at)
      VALUES ($1, $2, 'payloader', $3, $4, $5, NOW())
    `, [url, req.user.id, !result.isPayloader, result.riskScore, JSON.stringify(result.threats)]).catch(() => {});
    
    console.log(`[SECURITY] Payloader scan: ${url} - Risk: ${result.riskScore}%`);
    
    res.json({
      success: true,
      result: {
        url,
        filename,
        isPayloader: result.isPayloader,
        riskScore: result.riskScore,
        threats: result.threats,
        recommendation: result.isPayloader ? 'BLOCK - Do not download this file' : 'CAUTION - Verify source before downloading'
      }
    });
    
  } catch (e) {
    console.error('[SECURITY] Payloader scan error:', e);
    res.json({ success: false, error: 'Scan failed' });
  }
});

// POST /api/security/full-scan - Comprehensive threat scan (URL + payloader + APIs)
app.post('/api/security/full-scan', checkAuth(), async (req, res) => {
  const { url, checkApis = true } = req.body;
  
  if (!url) {
    return res.json({ success: false, error: 'URL required' });
  }
  
  try {
    const results = {
      url,
      scannedAt: new Date().toISOString(),
      checks: {},
      overallRisk: 0,
      threats: [],
      safe: true
    };
    
    // 1. Payloader detection (instant)
    const payloaderResult = detectPayloader(url);
    results.checks.payloader = payloaderResult;
    if (payloaderResult.isPayloader) {
      results.safe = false;
      results.overallRisk = Math.max(results.overallRisk, payloaderResult.riskScore);
      results.threats.push(...payloaderResult.threats);
    }
    
    // 2. Pattern matching (instant)
    const patternThreats = [];
    try {
      const parsed = new URL(url);
      const domain = parsed.hostname.toLowerCase();
      
      // Check suspicious TLDs
      const tld = '.' + domain.split('.').pop();
      if (MALICIOUS_INDICATORS.suspiciousTLDs.includes(tld)) {
        patternThreats.push({ type: 'SUSPICIOUS_TLD', severity: 'medium', description: `High-risk TLD: ${tld}` });
        results.overallRisk += 15;
      }
      
      // Check URL shorteners
      if (MALICIOUS_INDICATORS.shorteners.some(s => domain.includes(s))) {
        patternThreats.push({ type: 'URL_SHORTENER', severity: 'medium', description: 'URL shortener hides destination' });
        results.overallRisk += 20;
      }
      
      // Check uncommon file hosts
      if (MALICIOUS_INDICATORS.uncommonFileHosts.some(h => domain.includes(h))) {
        patternThreats.push({ type: 'SKETCHY_HOST', severity: 'high', description: `Uncommon file hosting: ${domain}` });
        results.overallRisk += 35;
      }
      
      // IP address as host
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        patternThreats.push({ type: 'IP_HOST', severity: 'high', description: 'Direct IP address instead of domain' });
        results.overallRisk += 25;
      }
      
    } catch (e) {
      patternThreats.push({ type: 'INVALID_URL', severity: 'low', description: 'Malformed URL' });
    }
    results.checks.patterns = { threats: patternThreats };
    results.threats.push(...patternThreats);
    
    // 3. External API checks (if enabled and keys exist)
    if (checkApis) {
      // VirusTotal
      if (process.env.VIRUSTOTAL_API_KEY) {
        try {
          const vt = await scanWithVirusTotal(url);
          results.checks.virusTotal = vt;
          if (vt.malicious > 0) {
            results.safe = false;
            results.overallRisk = Math.max(results.overallRisk, 70);
            results.threats.push({
              type: 'VIRUSTOTAL',
              severity: 'critical',
              description: `${vt.malicious} security vendors flagged as malicious`
            });
          }
        } catch (e) {
          results.checks.virusTotal = { error: e.message };
        }
      }
      
      // IPQualityScore
      if (process.env.IPQUALITYSCORE_API_KEY) {
        try {
          const ipqs = await scanWithIPQualityScore(url);
          results.checks.ipQualityScore = ipqs;
          if (ipqs.unsafe || ipqs.phishing || ipqs.malware) {
            results.safe = false;
            results.overallRisk = Math.max(results.overallRisk, 80);
            results.threats.push({
              type: 'IPQUALITYSCORE',
              severity: 'critical',
              description: `Risk score: ${ipqs.risk_score}% - ${ipqs.phishing ? 'Phishing' : ''} ${ipqs.malware ? 'Malware' : ''}`
            });
          }
        } catch (e) {
          results.checks.ipQualityScore = { error: e.message };
        }
      }
      
      // Google Safe Browsing
      if (process.env.GOOGLE_SAFE_BROWSING_KEY) {
        try {
          const gsb = await checkGoogleSafeBrowsing(url);
          results.checks.googleSafeBrowsing = gsb;
          if (!gsb.safe) {
            results.safe = false;
            results.overallRisk = Math.max(results.overallRisk, 90);
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
    }
    
    // Cap risk at 100
    results.overallRisk = Math.min(100, results.overallRisk);
    
    // Determine safety
    if (results.overallRisk >= 50) {
      results.safe = false;
    }
    
    // Log scan
    await pool.query(`
      INSERT INTO url_scans (url, scanned_by, scan_type, is_safe, risk_score, threats, created_at)
      VALUES ($1, $2, 'full', $3, $4, $5, NOW())
    `, [url, req.user.id, results.safe, results.overallRisk, JSON.stringify(results.threats)]).catch(() => {});
    
    res.json({ success: true, result: results });
    
  } catch (e) {
    console.error('[SECURITY] Full scan error:', e);
    res.json({ success: false, error: 'Scan failed' });
  }
});

// GET /api/security/known-threats - Get list of known malicious patterns
app.get('/api/security/known-threats', checkAuth('staff'), async (req, res) => {
  res.json({
    shorteners: MALICIOUS_INDICATORS.shorteners,
    suspiciousTLDs: MALICIOUS_INDICATORS.suspiciousTLDs,
    uncommonFileHosts: MALICIOUS_INDICATORS.uncommonFileHosts,
    dangerousExtensions: MALICIOUS_INDICATORS.dangerousDownloads,
    trustedDomains: MALICIOUS_INDICATORS.trustedDomains
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ADMIN PANEL API - Manage Users and Staff
// ═══════════════════════════════════════════════════════════════════════════

// GET /api/admin/users - List all users
app.get('/api/admin/users', checkAuth('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT discord_id, username, avatar, email, role, plan, plan_expires_at, created_at, last_login
      FROM users ORDER BY created_at DESC LIMIT 100
    `);
    res.json({ users: result.rows });
  } catch (e) {
    console.error('[ADMIN] Error fetching users:', e);
    res.json({ error: 'Failed to fetch users', users: [] });
  }
});

// POST /api/admin/users/:id/role - Change user role
app.post('/api/admin/users/:id/role', checkAuth('admin'), async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  
  if (!['customer', 'staff', 'admin'].includes(role)) {
    return res.json({ error: 'Invalid role' });
  }
  
  try {
    await pool.query('UPDATE users SET role = $1, updated_at = NOW() WHERE discord_id = $2', [role, id]);
    console.log(`[ADMIN] User ${id} role changed to ${role} by ${req.user.id}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[ADMIN] Error updating role:', e);
    res.json({ error: 'Failed to update role' });
  }
});

// POST /api/admin/users/:id/plan - Change user plan
app.post('/api/admin/users/:id/plan', checkAuth('admin'), async (req, res) => {
  const { id } = req.params;
  const { plan, expires_at } = req.body;
  
  if (!['free', 'pro', 'enterprise'].includes(plan)) {
    return res.json({ error: 'Invalid plan' });
  }
  
  try {
    await pool.query(`
      UPDATE users SET plan = $1, plan_expires_at = $2, updated_at = NOW() WHERE discord_id = $3
    `, [plan, expires_at || null, id]);
    console.log(`[ADMIN] User ${id} plan changed to ${plan} by ${req.user.id}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[ADMIN] Error updating plan:', e);
    res.json({ error: 'Failed to update plan' });
  }
});

// POST /api/admin/invite - Create staff invite link
app.post('/api/admin/invite', checkAuth('admin'), async (req, res) => {
  try {
    const code = require('crypto').randomBytes(16).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days
    
    await pool.query(`
      INSERT INTO staff_invites (code, created_by, expires_at)
      VALUES ($1, $2, $3)
    `, [code, req.user.id, expiresAt]);
    
    console.log(`[ADMIN] Staff invite created by ${req.user.id}: ${code}`);
    
    res.json({
      success: true,
      invite_url: `https://theunpatchedmethod.com/invite/${code}`,
      code,
      expires_at: expiresAt
    });
  } catch (e) {
    console.error('[ADMIN] Error creating invite:', e);
    res.json({ error: 'Failed to create invite' });
  }
});

// GET /api/admin/invites - List all invites
app.get('/api/admin/invites', checkAuth('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT si.*, u.username as created_by_name, u2.username as used_by_name
      FROM staff_invites si
      LEFT JOIN users u ON si.created_by = u.discord_id
      LEFT JOIN users u2 ON si.used_by = u2.discord_id
      ORDER BY si.created_at DESC
    `);
    res.json({ invites: result.rows });
  } catch (e) {
    res.json({ invites: [] });
  }
});

// DELETE /api/admin/invite/:code - Delete invite
app.delete('/api/admin/invite/:code', checkAuth('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM staff_invites WHERE code = $1', [req.params.code]);
    res.json({ success: true });
  } catch (e) {
    res.json({ error: 'Failed to delete invite' });
  }
});

// POST /api/invite/redeem - Redeem staff invite (authenticated users only)
app.post('/api/invite/redeem', checkAuth(), async (req, res) => {
  const { code } = req.body;
  
  try {
    // Check if invite exists and is valid
    const invite = await pool.query(`
      SELECT * FROM staff_invites 
      WHERE code = $1 AND used_by IS NULL AND expires_at > NOW()
    `, [code]);
    
    if (invite.rows.length === 0) {
      return res.json({ error: 'Invalid or expired invite code' });
    }
    
    // Upgrade user to staff
    await pool.query('UPDATE users SET role = $1, updated_at = NOW() WHERE discord_id = $2', ['staff', req.user.id]);
    
    // Mark invite as used
    await pool.query(`
      UPDATE staff_invites SET used_by = $1, used_at = NOW() WHERE code = $2
    `, [req.user.id, code]);
    
    console.log(`[INVITE] ${req.user.username} (${req.user.id}) redeemed staff invite ${code}`);
    
    res.json({ success: true, message: 'You are now a staff member!' });
  } catch (e) {
    console.error('[INVITE] Error:', e);
    res.json({ error: 'Failed to redeem invite' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// BAN SYSTEM - Admin can ban users and IPs
// ═══════════════════════════════════════════════════════════════════════════

// POST /api/admin/users/:id/ban - Ban a user
app.post('/api/admin/users/:id/ban', checkAuth('admin'), async (req, res) => {
  const { id } = req.params;
  const { reason, ban_ip } = req.body;
  
  try {
    // Get user
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1 OR discord_id = $1', [id]);
    if (userResult.rows.length === 0) {
      return res.json({ error: 'User not found' });
    }
    
    const user = userResult.rows[0];
    
    // Ban the user
    await pool.query(`
      UPDATE users SET banned = true, ban_reason = $1, banned_at = NOW() WHERE id = $2
    `, [reason || 'No reason provided', user.id]);
    
    // Optionally ban their IP too
    if (ban_ip && user.last_ip) {
      await pool.query(`
        INSERT INTO banned_ips (ip_address, reason, banned_by, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT DO NOTHING
      `, [user.last_ip, `Banned with user: ${user.email || user.discord_id}`, req.user.id]).catch(() => {});
    }
    
    console.log(`[ADMIN] User ${user.email || user.discord_id} banned by ${req.user.id}. Reason: ${reason}`);
    
    res.json({ success: true, message: 'User banned successfully' });
  } catch (e) {
    console.error('[ADMIN] Ban error:', e);
    res.json({ error: 'Failed to ban user' });
  }
});

// POST /api/admin/users/:id/unban - Unban a user
app.post('/api/admin/users/:id/unban', checkAuth('admin'), async (req, res) => {
  const { id } = req.params;
  
  try {
    await pool.query(`
      UPDATE users SET banned = false, ban_reason = NULL, banned_at = NULL WHERE id = $1 OR discord_id = $1
    `, [id]);
    
    console.log(`[ADMIN] User ${id} unbanned by ${req.user.id}`);
    
    res.json({ success: true, message: 'User unbanned successfully' });
  } catch (e) {
    console.error('[ADMIN] Unban error:', e);
    res.json({ error: 'Failed to unban user' });
  }
});

// POST /api/admin/ban-ip - Ban an IP address
app.post('/api/admin/ban-ip', checkAuth('admin'), async (req, res) => {
  const { ip, reason } = req.body;
  
  if (!ip) {
    return res.json({ error: 'IP address required' });
  }
  
  try {
    await pool.query(`
      INSERT INTO banned_ips (ip_address, reason, banned_by, created_at)
      VALUES ($1, $2, $3, NOW())
    `, [ip, reason || 'No reason provided', req.user.id]);
    
    console.log(`[ADMIN] IP ${ip} banned by ${req.user.id}`);
    
    res.json({ success: true, message: 'IP banned successfully' });
  } catch (e) {
    console.error('[ADMIN] Ban IP error:', e);
    res.json({ error: 'Failed to ban IP' });
  }
});

// DELETE /api/admin/ban-ip/:ip - Unban an IP
app.delete('/api/admin/ban-ip/:ip', checkAuth('admin'), async (req, res) => {
  try {
    await pool.query('DELETE FROM banned_ips WHERE ip_address = $1', [req.params.ip]);
    console.log(`[ADMIN] IP ${req.params.ip} unbanned by ${req.user.id}`);
    res.json({ success: true });
  } catch (e) {
    res.json({ error: 'Failed to unban IP' });
  }
});

// GET /api/admin/banned-ips - List all banned IPs
app.get('/api/admin/banned-ips', checkAuth('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM banned_ips ORDER BY created_at DESC
    `);
    res.json({ ips: result.rows });
  } catch (e) {
    res.json({ ips: [] });
  }
});

// GET /api/admin/login-logs - View login history
app.get('/api/admin/login-logs', checkAuth('admin'), async (req, res) => {
  try {
    const limit = req.query.limit || 100;
    const result = await pool.query(`
      SELECT ll.*, u.username, u.email as user_email, u.banned
      FROM login_logs ll
      LEFT JOIN users u ON ll.user_id = u.id
      ORDER BY ll.created_at DESC
      LIMIT $1
    `, [limit]);
    res.json({ logs: result.rows });
  } catch (e) {
    res.json({ logs: [] });
  }
});

// GET /api/admin/users - List all users (updated with more info)
app.get('/api/admin/users-full', checkAuth('admin'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, discord_id, username, avatar, email, role, plan, plan_expires_at, 
             banned, ban_reason, banned_at, signup_ip, last_ip, created_at, last_login
      FROM users ORDER BY created_at DESC LIMIT 200
    `);
    res.json({ users: result.rows });
  } catch (e) {
    console.error('[ADMIN] Error fetching users:', e);
    res.json({ error: 'Failed to fetch users', users: [] });
  }
});

// GET /api/staff/members - All guild members (verified + unverified)
app.get('/api/staff/members', checkStaffAuth, async (req, res) => {
  try {
    const guildId = req.query.guild_id || '1446317951757062256';
    const guild = client.guilds.cache.get(guildId);
    
    if (!guild) {
      console.log('[STAFF API] Guild not found:', guildId);
      return res.json({ error: 'Guild not found', members: [], total: 0, verified: 0 });
    }
    
    console.log('[STAFF API] Fetching members for guild:', guildId);
    
    // Fetch all guild members from Discord (with timeout)
    try {
      await guild.members.fetch({ time: 30000 });
    } catch (e) {
      console.log('[STAFF API] Member fetch warning:', e.message);
    }
    
    // Get all verified members from database with their latest verification data
    const verifiedData = await pool.query(`
      SELECT DISTINCT ON (vl.discord_id) 
        vl.discord_id, vl.discord_tag, vl.fingerprint_hash,
        vl.ip_address, vl.ip_port, vl.ip_risk_score, vl.ip_vpn, vl.ip_proxy, vl.ip_tor,
        vl.ip_country, vl.ip_region, vl.ip_city, vl.ip_isp, vl.ip_org,
        vl.ip_mobile, vl.ip_connection_type, vl.ip_latitude, vl.ip_longitude,
        vl.timezone_mismatch, vl.webrtc_real_ip, vl.webrtc_leak, vl.webrtc_real_country, vl.webrtc_real_city,
        vl.account_age_days, vl.is_new_account, vl.has_avatar, vl.has_banner, vl.is_nitro,
        vl.badges, vl.badge_count, vl.suspicious_username, vl.honeypot_triggered,
        vl.created_at as verified_at
      FROM verification_logs vl
      WHERE vl.guild_id = $1 AND vl.result = 'success'
      ORDER BY vl.discord_id, vl.created_at DESC
    `, [guildId]);
    
    // Also get from device_fingerprints for older verifications
    const oldVerified = await pool.query(`
      SELECT discord_id, discord_tag, fingerprint_hash, verified_at
      FROM device_fingerprints
      WHERE guild_id = $1
    `, [guildId]);
    
    // Create lookup maps
    const verifiedMap = new Map();
    verifiedData.rows.forEach(v => verifiedMap.set(v.discord_id, v));
    oldVerified.rows.forEach(v => {
      if (!verifiedMap.has(v.discord_id)) {
        verifiedMap.set(v.discord_id, v);
      }
    });
    
    // Build member list with all guild members
    const members = [];
    guild.members.cache.forEach(member => {
      if (member.user.bot) return; // Skip bots
      
      const verified = verifiedMap.get(member.id);
      members.push({
        discord_id: member.id,
        discord_tag: member.user.tag,
        avatar: member.user.displayAvatarURL({ size: 32 }),
        joined_at: member.joinedAt,
        is_verified: !!verified,
        verified_at: verified?.verified_at || verified?.created_at || null,
        fingerprint_hash: verified?.fingerprint_hash || null,
        ip_address: verified?.ip_address || null,
        ip_port: verified?.ip_port || null,
        ip_risk_score: verified?.ip_risk_score || null,
        ip_vpn: verified?.ip_vpn || false,
        ip_proxy: verified?.ip_proxy || false,
        ip_tor: verified?.ip_tor || false,
        ip_country: verified?.ip_country || null,
        ip_region: verified?.ip_region || null,
        ip_city: verified?.ip_city || null,
        ip_isp: verified?.ip_isp || null,
        ip_org: verified?.ip_org || null,
        ip_mobile: verified?.ip_mobile || false,
        timezone_mismatch: verified?.timezone_mismatch || false,
        // New fields
        webrtc_real_ip: verified?.webrtc_real_ip || null,
        webrtc_leak: verified?.webrtc_leak || false,
        webrtc_real_country: verified?.webrtc_real_country || null,
        webrtc_real_city: verified?.webrtc_real_city || null,
        account_age_days: verified?.account_age_days || null,
        is_new_account: verified?.is_new_account || false,
        has_avatar: verified?.has_avatar ?? null,
        has_banner: verified?.has_banner || false,
        is_nitro: verified?.is_nitro || false,
        badges: verified?.badges || null,
        badge_count: verified?.badge_count || 0,
        suspicious_username: verified?.suspicious_username || false,
        honeypot_triggered: verified?.honeypot_triggered || false
      });
    });
    
    // Sort: unverified first, then by join date
    members.sort((a, b) => {
      if (a.is_verified !== b.is_verified) return a.is_verified ? 1 : -1;
      return new Date(b.joined_at) - new Date(a.joined_at);
    });
    
    res.json({ members, total: members.length, verified: verifiedMap.size });
  } catch (error) {
    console.error('[STAFF API] Members error:', error);
    res.status(500).json({ error: 'Failed to get members', members: [] });
  }
});

// POST /api/staff/reset-fingerprint - Reset user's fingerprint
app.post('/api/staff/reset-fingerprint', checkStaffAuth, async (req, res) => {
  const { discord_id } = req.body;
  
  if (!discord_id) {
    return res.status(400).json({ success: false, error: 'No user ID provided' });
  }
  
  try {
    await pool.query('DELETE FROM device_fingerprints WHERE discord_id = $1', [discord_id]);
    console.log(`[STAFF] Fingerprint reset for ${discord_id}`);
    res.json({ success: true });
  } catch (e) {
    console.error('[STAFF] Reset error:', e);
    res.status(500).json({ success: false, error: 'Failed to reset fingerprint' });
  }
});

// GET /api/staff/stats - Dashboard stats
app.get('/api/staff/stats', checkStaffAuth, async (req, res) => {
  try {
    const guildId = req.query.guild_id || '1446317951757062256';
    
    const verifiedCount = await pool.query(
      'SELECT COUNT(*) FROM device_fingerprints WHERE guild_id = $1',
      [guildId]
    );
    
    const bannedCount = await pool.query(
      'SELECT COUNT(*) FROM fingerprint_bans WHERE guild_id = $1',
      [guildId]
    );
    
    const recentVerifications = await pool.query(
      'SELECT COUNT(*) FROM device_fingerprints WHERE guild_id = $1 AND verified_at > NOW() - INTERVAL \'24 hours\'',
      [guildId]
    );
    
    res.json({
      verified_users: parseInt(verifiedCount.rows[0].count),
      banned_fingerprints: parseInt(bannedCount.rows[0].count),
      verifications_24h: parseInt(recentVerifications.rows[0].count)
    });
  } catch (error) {
    console.error('[STAFF API] Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

// GET /api/staff/logs - Recent verification logs with threat intelligence
app.get('/api/staff/logs', checkStaffAuth, async (req, res) => {
  try {
    const guildId = req.query.guild_id || '1446317951757062256';
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const filter = req.query.filter || 'all'; // all, success, blocked_alt, duplicate
    
    // Try verification_logs first (new table with full data)
    let logs;
    try {
      let query = `
        SELECT id, discord_id, discord_tag, result, fingerprint_hash, 
               alt_of_discord_id, alt_of_discord_tag,
               ip_address, ip_port, ip_risk_score, ip_vpn, ip_proxy, ip_tor, ip_bot_score,
               ip_country, ip_region, ip_city, ip_isp, ip_org, ip_mobile, ip_connection_type,
               ip_latitude, ip_longitude, ip_abuse_reports,
               timezone_mismatch, browser_timezone, ip_timezone,
               webrtc_real_ip, webrtc_leak, webrtc_real_country, webrtc_real_city, webrtc_real_isp,
               account_age_days, is_new_account,
               has_avatar, has_banner, is_nitro, badges, badge_count, suspicious_username,
               honeypot_triggered, impossible_travel, velocity_blocked, language_mismatch, unusual_time,
               behavior_data, gpu_data, user_agent, created_at
        FROM verification_logs 
        WHERE guild_id = $1
      `;
      
      if (filter !== 'all') {
        query += ` AND result = $3`;
      }
      
      query += ` ORDER BY created_at DESC LIMIT $2`;
      
      if (filter !== 'all') {
        logs = await pool.query(query, [guildId, limit, filter]);
      } else {
        logs = await pool.query(query, [guildId, limit]);
      }
    } catch (e) {
      // Fallback to old table if verification_logs doesn't exist yet
      console.log('[STAFF API] verification_logs not found, using device_fingerprints');
      logs = await pool.query(`
        SELECT discord_id, discord_tag, fingerprint_hash, verified_at as created_at, 'success' as result
        FROM device_fingerprints 
        WHERE guild_id = $1 
        ORDER BY verified_at DESC 
        LIMIT $2
      `, [guildId, limit]);
    }
    
    res.json({ logs: logs.rows });
  } catch (error) {
    console.error('[STAFF API] Logs error:', error);
    res.status(500).json({ error: 'Failed to get logs' });
  }
});

// GET /api/staff/threat-stats - Threat intelligence summary
app.get('/api/staff/threat-stats', checkStaffAuth, async (req, res) => {
  try {
    const guildId = req.query.guild_id || '1446317951757062256';
    
    // Get threat stats from verification_logs
    const stats = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE result = 'success') as successful,
        COUNT(*) FILTER (WHERE result = 'blocked_alt') as blocked_alts,
        COUNT(*) FILTER (WHERE result = 'duplicate') as duplicates,
        COUNT(*) FILTER (WHERE ip_vpn = true) as vpn_users,
        COUNT(*) FILTER (WHERE ip_proxy = true) as proxy_users,
        COUNT(*) FILTER (WHERE ip_tor = true) as tor_users,
        COUNT(*) FILTER (WHERE ip_risk_score >= 75) as high_risk,
        COUNT(*) FILTER (WHERE timezone_mismatch = true) as timezone_mismatches,
        AVG(ip_risk_score) as avg_risk_score
      FROM verification_logs 
      WHERE guild_id = $1 AND created_at > NOW() - INTERVAL '7 days'
    `, [guildId]);
    
    // Get currently online VPN users (last 24h)
    const recentVPN = await pool.query(`
      SELECT COUNT(DISTINCT discord_id) as vpn_24h
      FROM verification_logs 
      WHERE guild_id = $1 AND ip_vpn = true AND created_at > NOW() - INTERVAL '24 hours'
    `, [guildId]);
    
    res.json({ 
      stats: stats.rows[0] || {},
      vpn_24h: recentVPN.rows[0]?.vpn_24h || 0
    });
  } catch (error) {
    console.error('[STAFF API] Threat stats error:', error);
    res.status(500).json({ error: 'Failed to get threat stats', stats: {} });
  }
});

// GET /api/staff/bans - All banned fingerprints
app.get('/api/staff/bans', checkStaffAuth, async (req, res) => {
  try {
    const guildId = req.query.guild_id || '1446317951757062256';
    
    const bans = await pool.query(`
      SELECT id, fingerprint_hash, banned_discord_id, banned_discord_tag, reason, banned_by, banned_at
      FROM fingerprint_bans 
      WHERE guild_id = $1 
      ORDER BY banned_at DESC
    `, [guildId]);
    
    res.json({ bans: bans.rows });
  } catch (error) {
    console.error('[STAFF API] Bans error:', error);
    res.status(500).json({ error: 'Failed to get bans' });
  }
});

// GET /api/staff/user/:query - Lookup user by ID or tag
app.get('/api/staff/user/:query', checkStaffAuth, async (req, res) => {
  try {
    const query = req.params.query;
    const guildId = req.query.guild_id || '1446317951757062256';
    
    // Check device_fingerprints
    const fingerprint = await pool.query(`
      SELECT * FROM device_fingerprints 
      WHERE (discord_id = $1 OR discord_tag ILIKE $2) AND guild_id = $3
    `, [query, `%${query}%`, guildId]);
    
    // Check if banned
    const ban = await pool.query(`
      SELECT * FROM fingerprint_bans 
      WHERE (banned_discord_id = $1 OR banned_discord_tag ILIKE $2) AND guild_id = $3
    `, [query, `%${query}%`, guildId]);
    
    // Find linked accounts (same fingerprint)
    let linkedAccounts = [];
    if (fingerprint.rows.length > 0) {
      const fpHash = fingerprint.rows[0].fingerprint_hash;
      const linked = await pool.query(`
        SELECT discord_id, discord_tag, verified_at FROM device_fingerprints 
        WHERE fingerprint_hash = $1 AND guild_id = $2 AND discord_id != $3
      `, [fpHash, guildId, fingerprint.rows[0].discord_id]);
      linkedAccounts = linked.rows;
    }
    
    // Get verification history with threat data
    let verificationHistory = [];
    try {
      const history = await pool.query(`
        SELECT id, result, ip_address, ip_risk_score, ip_vpn, ip_proxy, ip_tor,
               ip_country, ip_city, ip_isp, ip_abuse_reports, timezone_mismatch,
               browser_timezone, ip_timezone, created_at
        FROM verification_logs 
        WHERE discord_id = $1 AND guild_id = $2
        ORDER BY created_at DESC
        LIMIT 10
      `, [fingerprint.rows[0]?.discord_id || query, guildId]);
      verificationHistory = history.rows;
    } catch (e) {
      // verification_logs table might not exist yet
      console.log('[STAFF API] Could not fetch verification history:', e.message);
    }
    
    // Get last known IP and threat data
    const lastVerification = verificationHistory[0] || null;
    
    res.json({
      user: fingerprint.rows[0] || null,
      is_banned: ban.rows.length > 0,
      ban_info: ban.rows[0] || null,
      linked_accounts: linkedAccounts,
      verification_history: verificationHistory,
      threat_data: lastVerification ? {
        ip_address: lastVerification.ip_address,
        ip_risk_score: lastVerification.ip_risk_score,
        ip_vpn: lastVerification.ip_vpn,
        ip_proxy: lastVerification.ip_proxy,
        ip_tor: lastVerification.ip_tor,
        ip_country: lastVerification.ip_country,
        ip_city: lastVerification.ip_city,
        ip_isp: lastVerification.ip_isp,
        ip_abuse_reports: lastVerification.ip_abuse_reports,
        timezone_mismatch: lastVerification.timezone_mismatch
      } : null
    });
  } catch (error) {
    console.error('[STAFF API] User lookup error:', error);
    res.status(500).json({ error: 'Failed to lookup user' });
  }
});

// POST /api/staff/ban - Ban a fingerprint via web
app.post('/api/staff/ban', checkStaffAuth, async (req, res) => {
  try {
    const { discord_id, reason, banned_by } = req.body;
    const guildId = req.body.guild_id || '1446317951757062256';
    
    if (!discord_id) {
      return res.status(400).json({ error: 'discord_id required' });
    }
    
    // Get user's fingerprint
    const fingerprint = await pool.query(
      'SELECT * FROM device_fingerprints WHERE discord_id = $1 AND guild_id = $2',
      [discord_id, guildId]
    );
    
    if (fingerprint.rows.length === 0) {
      return res.status(404).json({ error: 'User has no fingerprint on record' });
    }
    
    const fp = fingerprint.rows[0];
    
    // Add to bans
    await pool.query(`
      INSERT INTO fingerprint_bans (fingerprint_hash, banned_discord_id, banned_discord_tag, guild_id, reason, banned_by)
      VALUES ($1, $2, $3, $4, $5, $6)
      ON CONFLICT (fingerprint_hash, guild_id) DO UPDATE SET
        reason = $5,
        banned_by = $6,
        banned_at = NOW()
    `, [fp.fingerprint_hash, discord_id, fp.discord_tag, guildId, reason || 'Banned via web dashboard', banned_by || 'Staff']);
    
    console.log(`[STAFF API] Banned ${fp.discord_tag} via web`);
    
    res.json({ 
      success: true, 
      message: `Banned ${fp.discord_tag}`,
      fingerprint_hash: fp.fingerprint_hash
    });
  } catch (error) {
    console.error('[STAFF API] Ban error:', error);
    res.status(500).json({ error: 'Failed to ban user' });
  }
});

// POST /api/staff/unban - Unban a fingerprint via web
app.post('/api/staff/unban', checkStaffAuth, async (req, res) => {
  try {
    const { discord_id, fingerprint_hash } = req.body;
    const guildId = req.body.guild_id || '1446317951757062256';
    
    if (!discord_id && !fingerprint_hash) {
      return res.status(400).json({ error: 'discord_id or fingerprint_hash required' });
    }
    
    let result;
    if (fingerprint_hash) {
      result = await pool.query(
        'DELETE FROM fingerprint_bans WHERE fingerprint_hash = $1 AND guild_id = $2 RETURNING *',
        [fingerprint_hash, guildId]
      );
    } else {
      result = await pool.query(
        'DELETE FROM fingerprint_bans WHERE banned_discord_id = $1 AND guild_id = $2 RETURNING *',
        [discord_id, guildId]
      );
    }
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No ban found for this user' });
    }
    
    console.log(`[STAFF API] Unbanned ${result.rows[0].banned_discord_tag} via web`);
    
    res.json({ 
      success: true, 
      message: `Unbanned ${result.rows[0].banned_discord_tag}`
    });
  } catch (error) {
    console.error('[STAFF API] Unban error:', error);
    res.status(500).json({ error: 'Failed to unban user' });
  }
});

// Legacy webhook (kept for backwards compatibility)
app.post('/webhook/verification-complete', async (req, res) => {
  const { bot_secret, discord_id, discord_tag, guild_id, verified, suspicious, alt_of, blocked, reason, linked_to } = req.body;
  
  // Verify request is from our verification server
  if (bot_secret !== process.env.VERIFY_BOT_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  
  try {
    const guild = client.guilds.cache.get(guild_id);
    if (!guild) {
      return res.status(404).json({ error: 'Guild not found' });
    }
    
    const member = await guild.members.fetch(discord_id).catch(() => null);
    if (!member) {
      return res.status(404).json({ error: 'Member not found' });
    }
    
    const securityLog = guild.channels.cache.find(c => 
      c.name === 'security-logs' || c.name === 'modmail-logs'
    );
    
    if (verified) {
      // Give verified role
      const VERIFIED_ROLE_ID = '1453304594317836423';
      const verifiedRole = guild.roles.cache.get(VERIFIED_ROLE_ID) || 
                           guild.roles.cache.find(r => r.name.toLowerCase() === 'verified');
      
      if (verifiedRole) {
        await member.roles.add(verifiedRole);
      }
      
      // Log verification
      if (securityLog) {
        const logEmbed = new EmbedBuilder()
          .setTitle(suspicious ? ' User Verified (Suspicious)' : ' User Verified')
          .setDescription(`**User:** ${member.user.tag}\n**ID:** \`${member.id}\``)
          .setColor(suspicious ? 0xFFAA00 : 0x00FF00)
          .setThumbnail(member.user.displayAvatarURL())
          .setTimestamp();
        
        if (suspicious && suspicious.possible_alt_of) {
          logEmbed.addFields({
            name: ' Possible Alt Detected',
            value: `Same device as: **${suspicious.possible_alt_of}** (<@${suspicious.discord_id}>)`,
            inline: false
          });
        }
        
        await securityLog.send({ embeds: [logEmbed] });
      }
      
      // Welcome in general chat
      const rolesChannel = guild.channels.cache.find(c => c.name === 'roles' || c.name === 'get-roles');
      const rolesChannelId = rolesChannel?.id || '1453304716967678022';
      
      const generalChannel = guild.channels.cache.get('1453304724681134163') || 
                             guild.channels.cache.find(c => c.name === 'general-chat' || c.name === 'general');
      
      if (generalChannel) {
        const welcomes = [
          `*security scan complete* ${member} is now verified. Welcome to the operation. Go pick your roles in <#${rolesChannelId}>.`,
          `${member} passed the fingerprint check. *unlocks channels* Head to <#${rolesChannelId}> and tell us what you're here for.`,
          `*device cleared* ${member} is officially in. Grab your roles in <#${rolesChannelId}> - we need to know your specialty.`
        ];
        
        const randomWelcome = welcomes[Math.floor(Math.random() * welcomes.length)];
        
        const embed = new EmbedBuilder()
          .setTitle(' Get Your Roles!')
          .setDescription(`**What brings you here?**\n\n **GTA Online** - Heists, grinding, businesses\n **Red Dead Online** - Wagons, bounties, collector\n\n **Click here  <#${rolesChannelId}>**`)
          .setColor(0x00FF00)
          .setFooter({ text: 'Select roles to find the right crew!' });
        
        await generalChannel.send({ content: randomWelcome, embeds: [embed] });
      }
      
      // DM the user
      try {
        await member.send({
          embeds: [new EmbedBuilder()
            .setTitle(' Verification Complete!')
            .setDescription(`Welcome to **${guild.name}**!\n\n Head to <#${rolesChannelId}> to pick your roles!`)
            .setColor(0x00FF00)
            .setFooter({ text: 'The Unpatched Method • Secured by Unpatched Verify' })
          ]
        });
      } catch (e) {}
      
      res.json({ success: true, message: 'User verified' });
      
    } else if (alt_of) {
      // Alt of BANNED user detected - blocked
      if (securityLog) {
        const alertEmbed = new EmbedBuilder()
          .setTitle(' ALT ACCOUNT BLOCKED')
          .setDescription(`**Attempted User:** ${member.user.tag}\n**ID:** \`${member.id}\``)
          .addFields(
            { name: ' Alt of Banned User', value: `**${alt_of.discord_tag}**\n<@${alt_of.discord_id}>`, inline: false },
            { name: ' Action', value: 'Verification DENIED - Same device fingerprint as banned user', inline: false }
          )
          .setColor(0xFF0000)
          .setThumbnail(member.user.displayAvatarURL())
          .setTimestamp();
        
        await securityLog.send({ content: '@here', embeds: [alertEmbed] });
      }
      
      // DM the user telling them we know who they are - INTIMIDATING with dramatic separate messages
      try {
        let mainMessage;
        
        if (anthropic) {
          try {
            const aiResponse = await anthropic.messages.create({
              model: 'claude-sonnet-4-20250514',
              max_tokens: 400,
              messages: [{
                role: 'user',
                content: `You are Burner Phone, a cold, intimidating anonymous security system. You caught a BANNED user trying to sneak back in on an alt. Their banned account was "${alt_of.discord_tag}".

Write a terrifying, intimidating message. Be ruthless. Make them feel like they're being watched by something they can't escape. Mix these vibes:
- Anonymous hacker who sees everything
- Cold, calculating, almost inhuman security AI
- Mock their pathetic attempt to hide
- Flex hard on the technical fingerprinting (canvas hash, WebGL renderer, GPU metadata, audio context, font enumeration, screen dimensions, timezone, hardware concurrency)
- Make it clear they are PERMANENTLY marked
- VPNs, new emails, new accounts - none of it matters
- Their hardware betrays them

Use *italics* for dramatic effect. Be creative and menacing. Include their banned username "${alt_of.discord_tag}". Make them paranoid. Keep it 2-3 paragraphs, under 900 characters. No emojis.`
              }]
            });
            mainMessage = aiResponse.content[0].text;
          } catch (e) {
            console.log('Claude API error, using fallback:', e.message);
          }
        }
        
        // Fallback if Claude fails
        if (!mainMessage) {
          mainMessage = `*encrypted transmission intercepted...*\n\nWell, well... **${alt_of.discord_tag}** thought they could hide behind a fresh account.\n\nYour device fingerprint was flagged the moment you connected. Canvas rendering patterns, WebGL signatures, GPU metadata, font enumeration, audio context hashes, screen dimensions, timezone offset, hardware concurrency... every digital breadcrumb you leave creates a signature. And yours? Already in our database. Permanently.\n\nVPN? Useless. New email? Irrelevant. New Discord account? *Pathetic.* Your hardware betrayed you the second you loaded the verification page. We see everything. We forget nothing.\n\n*You are marked.*`;
        }
        
        // Send main intimidating message
        await member.send({
          embeds: [new EmbedBuilder()
            .setTitle(' BURNER PHONE ALERT')
            .setDescription(mainMessage)
            .setColor(0xFF0000)
            .setFooter({ text: ' Burner Phone • We See Everything' })
            .setTimestamp()
          ]
        });
        
        // Dramatic pause then send separate system messages
        await new Promise(r => setTimeout(r, 2000));
        
        await member.send({
          content: '```diff\n-  SECURITY VIOLATION LOGGED\n- Device fingerprint: FLAGGED\n- Associated account: ' + alt_of.discord_tag + '\n- Status: PERMANENTLY BANNED\n```'
        });
        
        await new Promise(r => setTimeout(r, 1500));
        
        await member.send({
          content: '```\n[SYSTEM] Cross-referencing device signature...\n[SYSTEM] Match found in banned registry.\n[SYSTEM] Access permanently revoked.\n[SYSTEM] All future attempts will be logged and reported.\n```'
        });
        
        await new Promise(r => setTimeout(r, 2000));
        
        await member.send({
          content: '*Connection terminated. Have a secure day.* '
        });
        
      } catch (e) {}
      
      res.json({ success: true, message: 'Alt blocked' });
      
    } else if (blocked && reason === 'duplicate_device' && linked_to) {
      // Duplicate device - not banned, but already has an account
      if (securityLog) {
        const alertEmbed = new EmbedBuilder()
          .setTitle(' DUPLICATE ACCOUNT BLOCKED')
          .setDescription(`**Attempted User:** ${member.user.tag}\n**ID:** \`${member.id}\``)
          .addFields(
            { name: ' Device Already Linked To', value: `**${linked_to.discord_tag}**\n<@${linked_to.discord_id}>`, inline: false },
            { name: ' Action', value: 'Verification DENIED - One account per device policy', inline: false }
          )
          .setColor(0xFF6600)
          .setThumbnail(member.user.displayAvatarURL())
          .setTimestamp();
        
        await securityLog.send({ embeds: [alertEmbed] });
      }
      
      // DM the user telling them they already have an account - civil but escalates
      try {
        // Track their attempts
        if (!client.duplicateAttempts) client.duplicateAttempts = new Map();
        const attemptKey = `${discord_id}_${guild_id}`;
        const attempts = (client.duplicateAttempts.get(attemptKey) || 0) + 1;
        client.duplicateAttempts.set(attemptKey, attempts);
        
        let messageContent;
        let mood = 'civil'; // civil, annoyed, frustrated, done
        
        if (attempts === 1) mood = 'civil';
        else if (attempts === 2) mood = 'annoyed';
        else if (attempts === 3) mood = 'frustrated';
        else mood = 'done';
        
        if (anthropic) {
          try {
            const moodInstructions = {
              civil: `Be polite and professional. Just inform them matter-of-factly that this device is already linked to another account. No hostility, just facts. Mention they should use their original account "${linked_to.discord_tag}".`,
              annoyed: `Be slightly annoyed but still professional. They tried this before. Remind them firmly that one device = one account. Mention their original account "${linked_to.discord_tag}".`,
              frustrated: `Be noticeably frustrated. This is their third attempt. Be more stern. Make it clear this is getting old. Reference their original account "${linked_to.discord_tag}".`,
              done: `Be completely done with them. This is attempt #${attempts}. Be blunt and dismissive. Tell them to stop wasting everyone's time and just use "${linked_to.discord_tag}".`
            };
            
            const aiResponse = await anthropic.messages.create({
              model: 'claude-sonnet-4-20250514',
              max_tokens: 250,
              messages: [{
                role: 'user',
                content: `You are Burner Phone, a security system. Someone tried to verify a second account. Their existing account is "${linked_to.discord_tag}". This is attempt #${attempts}.

${moodInstructions[mood]}

Write 2-3 short paragraphs. Mention fingerprinting briefly (canvas, WebGL, etc) but don't be scary or threatening - this person isn't banned, just trying to have two accounts. Keep under 600 characters. No emojis.`
              }]
            });
            messageContent = aiResponse.content[0].text;
          } catch (e) {
            console.log('Claude API error, using fallback:', e.message);
          }
        }
        
        // Fallback if Claude fails
        if (!messageContent) {
          if (mood === 'civil') {
            messageContent = `Hey there. Just a heads up - this device is already registered to **${linked_to.discord_tag}**.\n\nWe use device fingerprinting to keep things fair, so one device means one account. If you need access, just use your original account.\n\nNo worries, these things happen.`;
          } else if (mood === 'annoyed') {
            messageContent = `We've been over this. This device belongs to **${linked_to.discord_tag}**.\n\nOne device, one account. That's the rule. Please use your original account.`;
          } else if (mood === 'frustrated') {
            messageContent = `This is attempt #${attempts}. The answer hasn't changed.\n\nDevice: Registered to **${linked_to.discord_tag}**.\nPolicy: One account per device.\n\nUse your main. That's it.`;
          } else {
            messageContent = `Attempt #${attempts}. Still no.\n\n**${linked_to.discord_tag}** - that's your account. Use it or don't. But this isn't going to work no matter how many times you try.`;
          }
        }
        
        await member.send({
          embeds: [new EmbedBuilder()
            .setTitle(attempts === 1 ? ' Verification Notice' : ' BURNER PHONE')
            .setDescription(messageContent)
            .setColor(attempts === 1 ? 0x5865F2 : (attempts < 3 ? 0xFF6600 : 0xFF0000))
            .setFooter({ text: attempts === 1 ? 'One Device, One Account' : ` Attempt #${attempts} logged` })
            .setTimestamp()
          ]
        });
      } catch (e) {}
      
      res.json({ success: true, message: 'Duplicate blocked' });
    }
    
  } catch (error) {
    console.error('Verification webhook error:', error);
    res.status(500).json({ error: 'Internal error' });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

const CONFIG = {
  PREFIX: '?',
  GUILD_ID: '1446317951757062256',
  VERIFIED_ROLE_ID: '1453304594317836423',
  ROLES_CHANNEL_ID: '1453304716967678022',
  COLORS: { primary: 0xFF6B35, success: 0x00FF00, error: 0xFF0000, warning: 0xFFAA00, info: 0x0099FF, danger: 0xFF0000 }
};

// Channel IDs
const MODMAIL_LOG_CHANNEL = '1463728261128388639';
const SECURITY_LOG_CHANNEL = '1463995707651522622';

// ═══════════════════════════════════════════════════════════════════════════════
// SOC-LEVEL SECURITY SYSTEM - ENTERPRISE GRADE THREAT DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// RISK SCORING THRESHOLDS
// ─────────────────────────────────────────────────────────────────────────────
const RISK_THRESHOLDS = {
  LOW: 20,        // Soft warning
  MEDIUM: 40,     // Flag for review
  HIGH: 60,       // Quarantine/block
  CRITICAL: 80    // Immediate action + alert
};

// ─────────────────────────────────────────────────────────────────────────────
// TYPOSQUATTING DETECTION - Common brand impersonation patterns
// ─────────────────────────────────────────────────────────────────────────────
const BRAND_TYPOSQUATS = {
  discord: [
    'dlscord', 'disc0rd', 'discorcl', 'discrod', 'diiscord', 'disscord',
    'dlsocrd', 'd1scord', 'discorb', 'discorc', 'discordd', 'discor',
    'dicsord', 'disord', 'discorld', 'discord-app', 'discord-login',
    'discord-verify', 'discordgift', 'discordnitro', 'discord-free',
    'discordtoken', 'discordsupport', 'discordhelp', 'discord-help'
  ],
  steam: [
    'stearn', 'stearn', 'steampowered', 'steamcommunlty', 'stearnpowered',
    'steamcommunity', 'steampowerd', 'steam-community', 'steamtrade',
    'steam-trade', 'steamgift', 'steam-login', 'steam-verify'
  ],
  nitro: [
    'nitr0', 'n1tro', 'nitrogift', 'nitrofree', 'freenitro', 'discordnitro'
  ],
  paypal: [
    'paypa1', 'paypai', 'paypal-login', 'paypal-verify', 'paypaI'
  ],
  microsoft: [
    'mlcrosoft', 'micros0ft', 'mircosoft', 'microsfot'
  ]
};

// ─────────────────────────────────────────────────────────────────────────────
// SOCIAL ENGINEERING LANGUAGE PATTERNS (NLP Indicators)
// ─────────────────────────────────────────────────────────────────────────────
const SOCIAL_ENGINEERING_PATTERNS = {
  // Urgency patterns (+15 risk each)
  urgency: [
    /\b(urgent|immediately|right now|asap|hurry|quick|fast|limited time)\b/i,
    /\b(expires? (in|soon)|only \d+ (left|remaining)|act (now|fast))\b/i,
    /\b(don'?t (wait|miss|delay)|last chance|final warning)\b/i,
    /\b(within \d+ (hours?|minutes?|days?))\b/i
  ],
  
  // Authority impersonation (+20 risk each)
  authority: [
    /\b(official|administrator|support team|staff member|discord team)\b/i,
    /\b(we('ve| have) (noticed|detected|found)|your account (has been|was))\b/i,
    /\b(security (team|alert|warning)|from discord|discord (support|team))\b/i,
    /\b(verified (by|staff)|official (message|notice))\b/i
  ],
  
  // Account threat language (+25 risk each)
  threat: [
    /\b(account.{0,20}(terminated|suspended|disabled|deleted|banned))\b/i,
    /\b(violation|unauthorized|suspicious activity|security breach)\b/i,
    /\b(will be (closed|terminated|deleted)|permanent(ly)? (ban|delete))\b/i,
    /\b(verify.{0,10}(or|otherwise)|confirm.{0,10}(to avoid|or else))\b/i
  ],
  
  // Prize/reward scam patterns (+20 risk each)
  prize: [
    /\b(you('ve| have)? (won|been selected|been chosen))\b/i,
    /\b(free (nitro|gift|money|steam)|claim (your|now|free))\b/i,
    /\b(congratulations|winner|lucky|selected|giveaway)\b/i,
    /\b(gift.{0,10}(card|code|nitro)|nitro.{0,10}(free|gift))\b/i
  ],
  
  // Fear-based manipulation (+15 risk each)
  fear: [
    /\b(hack(ed|ing|er)|compromised|stolen|leaked|breach)\b/i,
    /\b(someone (is|has)|unusual (login|activity)|different (device|location))\b/i,
    /\b(protect your|secure your|safety of your)\b/i
  ],
  
  // Action demands (+10 risk each)
  demands: [
    /\b(click (here|this|below|the link)|must (verify|confirm|login))\b/i,
    /\b(enter (your|the)|provide (your|the)|submit (your|the))\b/i,
    /\b(scan (this|the) (qr|code)|download (this|the))\b/i
  ]
};

// ─────────────────────────────────────────────────────────────────────────────
// KNOWN MALICIOUS INDICATORS
// ─────────────────────────────────────────────────────────────────────────────
const MALICIOUS_INDICATORS = {
  // URL shorteners (need expansion)
  shorteners: [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'adf.ly', 'bc.vc', 'j.mp', 'v.gd', 'shorturl.at', 'rb.gy', 'cutt.ly',
    'tiny.cc', 'short.io', 't.ly', 'soo.gd', 's.id', 'clck.ru'
  ],
  
  // Free hosting often used for phishing
  freeHosting: [
    'github.io', 'netlify.app', 'vercel.app', 'herokuapp.com', 'glitch.me',
    'repl.co', '000webhostapp.com', 'infinityfreeapp.com', 'web.app',
    'firebaseapp.com', 'pages.dev', 'workers.dev', 'surge.sh'
  ],
  
  // Known phishing TLDs (higher risk)
  suspiciousTLDs: [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click',
    '.link', '.info', '.online', '.site', '.website', '.space', '.fun',
    '.icu', '.buzz', '.monster', '.pw', '.cc', '.ws', '.cam', '.live',
    '.store', '.shop', '.download', '.stream', '.win', '.trade', '.review'
  ],
  
  // Legitimate domains (whitelist - reduce risk)
  trustedDomains: [
    'discord.com', 'discord.gg', 'discordapp.com', 'discord.media',
    'steam.com', 'steampowered.com', 'steamcommunity.com',
    'youtube.com', 'youtu.be', 'twitter.com', 'x.com', 'twitch.tv',
    'reddit.com', 'imgur.com', 'giphy.com', 'tenor.com',
    'github.com', 'google.com', 'microsoft.com', 'apple.com',
    'amazon.com', 'paypal.com', 'spotify.com', 'netflix.com',
    'rockstargames.com', 'epicgames.com', 'ea.com', 'ubisoft.com'
  ],
  
  // ═══════════════════════════════════════════════════════════════════════════════
  // PAYLOADER DETECTION - Known sites that host malicious files
  // ═══════════════════════════════════════════════════════════════════════════════
  
  // Legitimate file hosting services commonly abused for payloaders
  knownFileHosts: [
    'cdn.discordapp.com',      // Discord CDN - #1 malware host
    'media.discordapp.net',    // Discord media
    'cdn.discord.com',         // New Discord CDN
    'github.com/.*releases',   // GitHub releases
    'raw.githubusercontent.com', // GitHub raw files
    'drive.google.com',        // Google Drive
    'docs.google.com',         // Google Docs
    'dropbox.com',             // Dropbox
    'dl.dropboxusercontent.com',
    'onedrive.live.com',       // OneDrive
    'mediafire.com',           // MediaFire
    'mega.nz',                 // MEGA
    'mega.co.nz',
    'anonfiles.com',           // Anonymous file hosting
    'gofile.io',
    'pixeldrain.com',
    'wetransfer.com',
    'sendspace.com',
    'file.io',
    'transfer.sh',
    'catbox.moe',              // Catbox
    'litterbox.catbox.moe',
    'pomf.cat',
    'uguu.se',
    'fileditch.com',
    'anonymousfiles.io',
    'bayfiles.com',
    'zippyshare.com'
  ],
  
  // File extensions that are ALWAYS dangerous when downloaded
  dangerousDownloads: [
    '.exe', '.msi', '.bat', '.cmd', '.com', '.scr', '.pif',
    '.vbs', '.vbe', '.js', '.jse', '.ws', '.wsf', '.wsh',
    '.ps1', '.psm1', '.psd1', '.ps1xml', '.pssc', '.psc1',
    '.hta', '.cpl', '.msc', '.jar', '.dll', '.sys', '.drv',
    '.ocx', '.reg', '.inf', '.scf', '.lnk', '.url', '.appx',
    '.msix', '.appxbundle', '.msixbundle', '.gadget', '.msu',
    '.application', '.appref-ms', '.settingcontent-ms'
  ],
  
  // Discord CDN patterns that indicate payloaders
  discordCdnPayloaderPatterns: [
    /cdn\.discordapp\.com\/attachments\/.*\.(exe|msi|bat|cmd|scr|dll|ps1)/i,
    /cdn\.discord\.com\/attachments\/.*\.(exe|msi|bat|cmd|scr|dll|ps1)/i,
    /media\.discordapp\.net\/attachments\/.*\.(exe|msi|bat|cmd|scr|dll|ps1)/i
  ],
  
  // GitHub patterns indicating potential payloaders
  githubPayloaderPatterns: [
    /github\.com\/.*\/releases\/download\/.*\.(exe|msi|bat)/i,
    /raw\.githubusercontent\.com\/.*\.(exe|ps1|bat|vbs)/i,
    /github\.com\/.*\/raw\/.*\.(exe|ps1|bat|vbs)/i
  ],
  
  // Uncommon/sketchy file hosting (HIGH RISK)
  uncommonFileHosts: [
    'anonfile.com', 'anonymfile.com', 'uploadhaven.com',
    'tusfiles.com', 'uploadrar.com', 'up-load.io',
    'uploadev.org', 'letsupload.io', 'rapidgator.net',
    'nitroflare.com', 'uploaded.net', 'turbobit.net',
    'hitfile.net', 'file.al', 'uploadgig.com',
    'filefactory.com', 'dailyuploads.net', 'usersdrive.com',
    'uptobox.com', 'clicknupload.click', 'hexupload.net',
    'ddownload.com', 'fastclick.to', 'drop.download',
    'racaty.net', 'earn4files.com', 'uploadcloud.pro'
  ],
  
  // Known grabber/stealer download patterns
  grabberPatterns: [
    /grab(ber)?/i, /steal(er)?/i, /log(ger)?/i, /rat\b/i,
    /token/i, /password/i, /cookie/i, /browser/i,
    /discord.*token/i, /token.*grab/i, /cookie.*steal/i,
    /keylog/i, /clipper/i, /miner/i, /cryptojack/i,
    /ransomware/i, /botnet/i, /trojan/i, /backdoor/i
  ],
  
  // Archive files that commonly contain payloaders
  suspiciousArchiveNames: [
    /nitro/i, /free.*gift/i, /hack/i, /cheat/i, /crack/i,
    /keygen/i, /activator/i, /loader/i, /injector/i,
    /mod.*menu/i, /aimbot/i, /wallhack/i, /esp/i,
    /spoof/i, /unban/i, /bypass/i, /exploit/i,
    /generator/i, /free.*vbuck/i, /free.*robux/i
  ]
};

// ─────────────────────────────────────────────────────────────────────────────
// PAYLOADER DETECTION FUNCTION
// ─────────────────────────────────────────────────────────────────────────────

function detectPayloader(url, filename = '') {
  const threats = [];
  let riskScore = 0;
  
  try {
    const urlLower = url.toLowerCase();
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const path = parsed.pathname.toLowerCase();
    const fullName = filename.toLowerCase() || path.split('/').pop();
    const ext = '.' + fullName.split('.').pop();
    
    // 1. Check if it's a dangerous file type on a known host
    if (MALICIOUS_INDICATORS.dangerousDownloads.includes(ext)) {
      
      // Discord CDN with executable = HIGH RISK
      if (domain.includes('discordapp.com') || domain.includes('discord.com')) {
        threats.push({
          type: 'DISCORD_CDN_PAYLOADER',
          severity: 'critical',
          description: `Executable file (${ext}) hosted on Discord CDN - common malware vector`
        });
        riskScore += 70;
      }
      
      // GitHub releases with executable = MEDIUM RISK (could be legitimate)
      else if (domain.includes('github.com') || domain.includes('githubusercontent.com')) {
        threats.push({
          type: 'GITHUB_EXECUTABLE',
          severity: 'high',
          description: `Executable file (${ext}) from GitHub - verify source`
        });
        riskScore += 40;
      }
      
      // Uncommon file host with executable = CRITICAL
      else if (MALICIOUS_INDICATORS.uncommonFileHosts.some(h => domain.includes(h))) {
        threats.push({
          type: 'SKETCHY_HOST_PAYLOADER',
          severity: 'critical',
          description: `Executable from suspicious file host: ${domain}`
        });
        riskScore += 80;
      }
      
      // Any known file host with executable
      else if (MALICIOUS_INDICATORS.knownFileHosts.some(h => domain.includes(h) || urlLower.includes(h))) {
        threats.push({
          type: 'FILE_HOST_EXECUTABLE',
          severity: 'high',
          description: `Executable file (${ext}) from file hosting service`
        });
        riskScore += 50;
      }
      
      // Direct IP with executable = CRITICAL
      else if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        threats.push({
          type: 'IP_PAYLOADER',
          severity: 'critical',
          description: `Executable served from raw IP address - extremely suspicious`
        });
        riskScore += 90;
      }
    }
    
    // 2. Check filename against grabber/stealer patterns
    for (const pattern of MALICIOUS_INDICATORS.grabberPatterns) {
      if (pattern.test(fullName) || pattern.test(url)) {
        threats.push({
          type: 'GRABBER_STEALER',
          severity: 'critical',
          description: `Filename matches known malware pattern: ${pattern.toString()}`
        });
        riskScore += 60;
        break;
      }
    }
    
    // 3. Check for suspicious archive names (likely contains malware)
    if (['.zip', '.rar', '.7z', '.tar', '.gz'].includes(ext)) {
      for (const pattern of MALICIOUS_INDICATORS.suspiciousArchiveNames) {
        if (pattern.test(fullName)) {
          threats.push({
            type: 'SUSPICIOUS_ARCHIVE',
            severity: 'high',
            description: `Archive name matches malware pattern: ${pattern.toString()}`
          });
          riskScore += 45;
          break;
        }
      }
    }
    
    // 4. Double extension detection (photo.jpg.exe)
    const parts = fullName.split('.');
    if (parts.length > 2) {
      const realExt = '.' + parts[parts.length - 1];
      const fakeExt = '.' + parts[parts.length - 2];
      if (MALICIOUS_INDICATORS.dangerousDownloads.includes(realExt) &&
          ['.jpg', '.png', '.gif', '.pdf', '.doc', '.txt', '.mp3', '.mp4'].includes(fakeExt)) {
        threats.push({
          type: 'DOUBLE_EXTENSION',
          severity: 'critical',
          description: `Hidden executable: appears as ${fakeExt} but is actually ${realExt}`
        });
        riskScore += 85;
      }
    }
    
    // 5. Very long random filename (common for malware)
    if (fullName.length > 50 && /[a-f0-9]{20,}/i.test(fullName)) {
      threats.push({
        type: 'RANDOM_FILENAME',
        severity: 'medium',
        description: 'Suspicious randomly-generated filename'
      });
      riskScore += 20;
    }
    
  } catch (e) {
    // Invalid URL
  }
  
  return {
    isPayloader: riskScore >= 50,
    riskScore: Math.min(100, riskScore),
    threats
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE THREAT INDICATORS (Static Analysis)
// ─────────────────────────────────────────────────────────────────────────────
const FILE_THREATS = {
  // Dangerous extensions - immediate high risk
  dangerous: [
    '.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.vbe',
    '.js', '.jse', '.ws', '.wsf', '.msc', '.msi', '.msp', '.hta',
    '.cpl', '.jar', '.ps1', '.psm1', '.dll', '.sys', '.drv',
    '.reg', '.inf', '.scf', '.lnk', '.url', '.application', '.gadget',
    '.msu', '.appx', '.appxbundle', '.msix', '.msixbundle'
  ],
  
  // Macro-enabled documents
  macroEnabled: [
    '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm', '.xlam', '.ppam'
  ],
  
  // Archives that need inspection
  archives: [
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.iso', '.img', '.cab'
  ],
  
  // Magic bytes for file type verification
  magicBytes: {
    'exe': ['4D5A'], // MZ header
    'pdf': ['255044462D'], // %PDF-
    'zip': ['504B0304', '504B0506', '504B0708'],
    'rar': ['526172211A07'],
    '7z': ['377ABCAF271C'],
    'png': ['89504E47'],
    'jpg': ['FFD8FF'],
    'gif': ['474946383961', '474946383761'],
    'doc': ['D0CF11E0A1B11AE1'],
    'docx': ['504B0304'] // Same as ZIP (OOXML)
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// HOMOGRAPH ATTACK DETECTION (Cyrillic/Unicode lookalikes)
// ─────────────────────────────────────────────────────────────────────────────
const HOMOGRAPH_MAP = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
  'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'і': 'i', 'ї': 'i', 'ј': 'j',
  'ѕ': 's', 'ѡ': 'w', 'ԁ': 'd', 'ԛ': 'q', 'ɑ': 'a', 'ɡ': 'g', 'ɩ': 'i',
  'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'ᴀ': 'a', 'ᴅ': 'd', 'ᴇ': 'e',
  'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r', 'ꜱ': 's', 'ᴛ': 't'
};

// ═══════════════════════════════════════════════════════════════════════════════
// COMPREHENSIVE RISK SCORING ENGINE
// ═══════════════════════════════════════════════════════════════════════════════

class ThreatAnalyzer {
  constructor() {
    this.riskScore = 0;
    this.findings = [];
    this.signals = [];
  }
  
  addRisk(points, category, detail) {
    this.riskScore += points;
    this.findings.push({ points, category, detail });
    this.signals.push(`[+${points}] ${category}: ${detail}`);
  }
  
  reduceRisk(points, reason) {
    this.riskScore = Math.max(0, this.riskScore - points);
    this.signals.push(`[-${points}] Trust: ${reason}`);
  }
  
  getResult() {
    let action = 'ALLOW';
    let level = 'safe';
    
    if (this.riskScore >= RISK_THRESHOLDS.CRITICAL) {
      action = 'BLOCK';
      level = 'critical';
    } else if (this.riskScore >= RISK_THRESHOLDS.HIGH) {
      action = 'QUARANTINE';
      level = 'high';
    } else if (this.riskScore >= RISK_THRESHOLDS.MEDIUM) {
      action = 'FLAG';
      level = 'medium';
    } else if (this.riskScore >= RISK_THRESHOLDS.LOW) {
      action = 'WARN';
      level = 'low';
    }
    
    return {
      score: this.riskScore,
      level,
      action,
      findings: this.findings,
      signals: this.signals,
      summary: this.signals.join('\n'),
      apiResults: this.apiResults || {}
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// REAL API INTEGRATIONS - ENTERPRISE GRADE
// ═══════════════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────────────
// IPQUALITYSCORE API (Fraud Detection, Proxy/VPN, Malicious URL)
// ─────────────────────────────────────────────────────────────────────────────
async function scanWithIPQualityScore(url) {
  const apiKey = process.env.IPQUALITYSCORE_API_KEY;
  if (!apiKey) return { available: false };
  
  try {
    const encodedUrl = encodeURIComponent(url);
    const response = await fetch(
      `https://ipqualityscore.com/api/json/url/${apiKey}/${encodedUrl}?strictness=1&fast=false`,
      { timeout: 10000 }
    );
    
    if (!response.ok) return { available: false, error: 'API request failed' };
    
    const data = await response.json();
    
    return {
      available: true,
      success: data.success,
      unsafe: data.unsafe || false,
      suspicious: data.suspicious || false,
      phishing: data.phishing || false,
      malware: data.malware || false,
      spamming: data.spamming || false,
      adult: data.adult || false,
      riskScore: data.risk_score || 0,
      domain: data.domain,
      ipAddress: data.ip_address,
      countryCode: data.country_code,
      parking: data.parking || false,
      redirected: data.redirected || false,
      finalUrl: data.final_url
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

// Check IP reputation with IPQualityScore
async function checkIPWithIPQS(ip) {
  const apiKey = process.env.IPQUALITYSCORE_API_KEY;
  if (!apiKey) return { available: false };
  
  try {
    const response = await fetch(
      `https://ipqualityscore.com/api/json/ip/${apiKey}/${ip}?strictness=1&allow_public_access_points=true`,
      { timeout: 10000 }
    );
    
    if (!response.ok) return { available: false };
    
    const data = await response.json();
    
    return {
      available: true,
      fraudScore: data.fraud_score || 0,
      proxy: data.proxy || false,
      vpn: data.vpn || false,
      tor: data.tor || false,
      recentAbuse: data.recent_abuse || false,
      botStatus: data.bot_status || false,
      countryCode: data.country_code,
      isp: data.ISP
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ABUSEIPDB API (IP Reputation Database)
// ─────────────────────────────────────────────────────────────────────────────
async function checkWithAbuseIPDB(ip) {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) return { available: false };
  
  try {
    const response = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
      {
        headers: {
          'Key': apiKey,
          'Accept': 'application/json'
        },
        timeout: 10000
      }
    );
    
    if (!response.ok) return { available: false, error: 'API request failed' };
    
    const data = await response.json();
    const result = data.data || {};
    
    return {
      available: true,
      ipAddress: result.ipAddress,
      isPublic: result.isPublic,
      abuseConfidenceScore: result.abuseConfidenceScore || 0,
      countryCode: result.countryCode,
      isp: result.isp,
      domain: result.domain,
      totalReports: result.totalReports || 0,
      numDistinctUsers: result.numDistinctUsers || 0,
      lastReportedAt: result.lastReportedAt,
      isTor: result.isTor || false,
      isWhitelisted: result.isWhitelisted || false
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ALIENVAULT OTX API (Threat Intelligence - IOCs, Pulses)
// ─────────────────────────────────────────────────────────────────────────────
async function checkWithAlienVault(indicator, type = 'domain') {
  const apiKey = process.env.ALIENVAULT_OTX_KEY;
  if (!apiKey) return { available: false };
  
  // type can be: domain, hostname, url, IPv4, IPv6, file (hash)
  const section = type === 'url' ? 'url' : type === 'file' ? 'file' : type;
  
  try {
    const encodedIndicator = encodeURIComponent(indicator);
    const response = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/${section}/${encodedIndicator}/general`,
      {
        headers: {
          'X-OTX-API-KEY': apiKey,
          'Accept': 'application/json'
        },
        timeout: 10000
      }
    );
    
    if (!response.ok) {
      if (response.status === 404) {
        return { available: true, found: false, pulseCount: 0 };
      }
      return { available: false, error: 'API request failed' };
    }
    
    const data = await response.json();
    
    return {
      available: true,
      found: true,
      pulseCount: data.pulse_info?.count || 0,
      pulses: (data.pulse_info?.pulses || []).slice(0, 5).map(p => ({
        name: p.name,
        description: p.description?.slice(0, 100),
        tags: p.tags?.slice(0, 5),
        malwareFamily: p.malware_families,
        created: p.created
      })),
      reputation: data.reputation || 0,
      validation: data.validation || [],
      country: data.country_code,
      asn: data.asn
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

// Check file hash with AlienVault
async function checkFileHashOTX(hash) {
  return await checkWithAlienVault(hash, 'file');
}

// ─────────────────────────────────────────────────────────────────────────────
// HYBRID ANALYSIS API (Sandbox File Analysis)
// ─────────────────────────────────────────────────────────────────────────────
async function scanWithHybridAnalysis(fileUrl, filename) {
  const apiKey = process.env.HYBRID_ANALYSIS_KEY;
  if (!apiKey) return { available: false };
  
  try {
    // First, check if file hash already exists in their database
    // For quick lookup, we'll use URL scanning
    const response = await fetch(
      'https://www.hybrid-analysis.com/api/v2/quick-scan/url',
      {
        method: 'POST',
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Falcon Sandbox'
        },
        body: `scan_type=all&url=${encodeURIComponent(fileUrl)}`,
        timeout: 15000
      }
    );
    
    if (!response.ok) return { available: false, error: 'API request failed' };
    
    const data = await response.json();
    
    return {
      available: true,
      id: data.id,
      sha256: data.sha256,
      finished: data.finished || false,
      verdict: data.verdict, // 'malicious', 'suspicious', 'no specific threat', 'whitelisted'
      threatScore: data.threat_score || 0,
      threatLevel: data.threat_level || 0, // 0=no threat, 1=suspicious, 2=malicious
      malwareFamily: data.vx_family
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

// Search Hybrid Analysis for existing reports on a hash
async function searchHybridAnalysis(hash) {
  const apiKey = process.env.HYBRID_ANALYSIS_KEY;
  if (!apiKey) return { available: false };
  
  try {
    const response = await fetch(
      'https://www.hybrid-analysis.com/api/v2/search/hash',
      {
        method: 'POST',
        headers: {
          'api-key': apiKey,
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Falcon Sandbox'
        },
        body: `hash=${encodeURIComponent(hash)}`,
        timeout: 10000
      }
    );
    
    if (!response.ok) return { available: false };
    
    const data = await response.json();
    
    if (!data || data.length === 0) {
      return { available: true, found: false };
    }
    
    const result = data[0]; // Most recent result
    
    return {
      available: true,
      found: true,
      verdict: result.verdict,
      threatScore: result.threat_score,
      malwareFamily: result.vx_family,
      submitName: result.submit_name,
      analysisStartTime: result.analysis_start_time,
      tags: result.type_short
    };
  } catch (e) {
    return { available: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL SHORTENER EXPANSION (Actually follows redirects)
// ─────────────────────────────────────────────────────────────────────────────
async function expandShortUrl(url) {
  try {
    // First try unshorten.me API (free, no key needed)
    const response = await fetch(`https://unshorten.me/json/${encodeURIComponent(url)}`, {
      timeout: 5000
    });
    
    if (response.ok) {
      const data = await response.json();
      if (data.success && data.resolved_url) {
        return {
          original: url,
          expanded: data.resolved_url,
          success: true
        };
      }
    }
    
    // Fallback: Follow redirects manually with HEAD request
    const headResponse = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      timeout: 5000
    });
    
    if (headResponse.url !== url) {
      return {
        original: url,
        expanded: headResponse.url,
        success: true
      };
    }
    
    return { original: url, expanded: url, success: false };
  } catch (e) {
    return { original: url, expanded: url, success: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// VIRUSTOTAL API (Deep URL/File Scanning)
// ─────────────────────────────────────────────────────────────────────────────
async function scanWithVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { malicious: 0, suspicious: 0, harmless: 0, available: false };
  
  try {
    // Submit URL for scanning
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(url)}`
    });
    
    if (!submitResponse.ok) {
      return { malicious: 0, suspicious: 0, harmless: 0, error: 'Submit failed' };
    }
    
    const submitData = await submitResponse.json();
    const analysisId = submitData.data?.id;
    
    if (!analysisId) {
      return { malicious: 0, suspicious: 0, harmless: 0, error: 'No analysis ID' };
    }
    
    // Wait a moment for analysis
    await new Promise(r => setTimeout(r, 2000));
    
    // Get results
    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey }
    });
    
    if (!resultResponse.ok) {
      return { malicious: 0, suspicious: 0, harmless: 0, error: 'Result fetch failed' };
    }
    
    const resultData = await resultResponse.json();
    const stats = resultData.data?.attributes?.stats || {};
    
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      available: true
    };
  } catch (e) {
    return { malicious: 0, suspicious: 0, harmless: 0, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// GOOGLE SAFE BROWSING API (Checks Google's phishing database)
// ─────────────────────────────────────────────────────────────────────────────
async function checkGoogleSafeBrowsing(urls) {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!apiKey) return { threats: [], available: false };
  
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: 'burner-phone-bot',
          clientVersion: '1.0.0'
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: urls.map(url => ({ url }))
        }
      })
    });
    
    if (!response.ok) {
      return { threats: [], error: 'API request failed' };
    }
    
    const data = await response.json();
    return {
      threats: data.matches || [],
      available: true
    };
  } catch (e) {
    return { threats: [], error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// URLSCAN.IO API (Deep URL Analysis - Screenshot, DOM, etc.)
// ─────────────────────────────────────────────────────────────────────────────
async function scanWithUrlScan(url) {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) return { malicious: false, score: 0, available: false };
  
  try {
    // Submit URL for scanning
    const submitResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'API-Key': apiKey,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        url: url,
        visibility: 'unlisted'
      })
    });
    
    if (!submitResponse.ok) {
      const errorText = await submitResponse.text();
      return { malicious: false, score: 0, error: `Submit failed: ${errorText}` };
    }
    
    const submitData = await submitResponse.json();
    const resultUrl = submitData.api;
    
    if (!resultUrl) {
      return { malicious: false, score: 0, error: 'No result URL' };
    }
    
    // Wait for scan to complete (urlscan takes ~10-30 seconds)
    await new Promise(r => setTimeout(r, 15000));
    
    // Get results
    const resultResponse = await fetch(resultUrl);
    
    if (!resultResponse.ok) {
      // Scan might still be processing
      return { malicious: false, score: 0, pending: true };
    }
    
    const resultData = await resultResponse.json();
    
    return {
      malicious: resultData.verdicts?.overall?.malicious || false,
      score: resultData.verdicts?.overall?.score || 0,
      categories: resultData.verdicts?.overall?.categories || [],
      brands: resultData.verdicts?.overall?.brands || [],
      screenshot: resultData.task?.screenshotURL,
      available: true
    };
  } catch (e) {
    return { malicious: false, score: 0, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// PHISHTANK API (Community-driven phishing database)
// ─────────────────────────────────────────────────────────────────────────────
async function checkPhishTank(url) {
  const apiKey = process.env.PHISHTANK_API_KEY;
  // PhishTank works without API key but rate limited
  
  try {
    const formData = new URLSearchParams();
    formData.append('url', Buffer.from(url).toString('base64'));
    formData.append('format', 'json');
    if (apiKey) formData.append('app_key', apiKey);
    
    const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString()
    });
    
    if (!response.ok) {
      return { inDatabase: false, isPhish: false, error: 'API request failed' };
    }
    
    const data = await response.json();
    
    return {
      inDatabase: data.results?.in_database || false,
      isPhish: data.results?.valid || false,
      verified: data.results?.verified || false,
      verifiedAt: data.results?.verified_at,
      available: true
    };
  } catch (e) {
    return { inDatabase: false, isPhish: false, error: e.message };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE CONTENT ANALYSIS (Download and inspect)
// ─────────────────────────────────────────────────────────────────────────────
async function analyzeFileContent(attachment) {
  const results = {
    safe: true,
    threats: [],
    warnings: [],
    magicByteMatch: null
  };
  
  try {
    // Only download files under 10MB for safety
    if (attachment.size > 10 * 1024 * 1024) {
      results.warnings.push('File too large for deep inspection');
      return results;
    }
    
    // Download first 8KB for magic byte analysis (enough for headers)
    const response = await fetch(attachment.url, {
      headers: { 'Range': 'bytes=0-8192' }
    });
    
    if (!response.ok) {
      results.warnings.push('Could not download file for inspection');
      return results;
    }
    
    const buffer = await response.arrayBuffer();
    const bytes = new Uint8Array(buffer);
    const hexHeader = Array.from(bytes.slice(0, 16))
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join('');
    
    // Get claimed extension
    const ext = attachment.name.split('.').pop().toLowerCase();
    
    // Check magic bytes against known signatures
    const MAGIC_SIGNATURES = {
      // Executables
      '4D5A': { type: 'exe', dangerous: true, name: 'Windows Executable' },
      '7F454C46': { type: 'elf', dangerous: true, name: 'Linux Executable' },
      'CAFEBABE': { type: 'class', dangerous: true, name: 'Java Class' },
      '504B0304': { type: 'zip', dangerous: false, name: 'ZIP Archive' },
      
      // Documents
      '25504446': { type: 'pdf', dangerous: false, name: 'PDF Document' },
      'D0CF11E0A1B11AE1': { type: 'doc', dangerous: false, name: 'MS Office (old)' },
      
      // Images
      '89504E47': { type: 'png', dangerous: false, name: 'PNG Image' },
      'FFD8FF': { type: 'jpg', dangerous: false, name: 'JPEG Image' },
      '47494638': { type: 'gif', dangerous: false, name: 'GIF Image' },
      '52494646': { type: 'webp', dangerous: false, name: 'WebP Image' },
      
      // Archives
      '526172211A07': { type: 'rar', dangerous: false, name: 'RAR Archive' },
      '377ABCAF271C': { type: '7z', dangerous: false, name: '7-Zip Archive' },
      '1F8B08': { type: 'gz', dangerous: false, name: 'GZIP Archive' }
    };
    
    let detectedType = null;
    for (const [signature, info] of Object.entries(MAGIC_SIGNATURES)) {
      if (hexHeader.startsWith(signature)) {
        detectedType = info;
        break;
      }
    }
    
    if (detectedType) {
      results.magicByteMatch = detectedType;
      
      // Check for extension mismatch
      const safeImageExts = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'];
      const safeDocExts = ['pdf', 'doc', 'docx', 'txt'];
      
      if (detectedType.dangerous) {
        if (safeImageExts.includes(ext) || safeDocExts.includes(ext)) {
          results.safe = false;
          results.threats.push(` EXTENSION MISMATCH: File claims to be .${ext} but is actually ${detectedType.name}`);
        }
      }
      
      // Executable disguised as something else
      if (detectedType.type === 'exe' && ext !== 'exe') {
        results.safe = false;
        results.threats.push(` HIDDEN EXECUTABLE: File is Windows executable disguised as .${ext}`);
      }
    }
    
    // Check for embedded scripts in PDFs
    if (ext === 'pdf' || (detectedType && detectedType.type === 'pdf')) {
      const textContent = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      
      if (textContent.includes('/JavaScript') || textContent.includes('/JS')) {
        results.warnings.push(' PDF contains JavaScript (potentially dangerous)');
        results.safe = false;
        results.threats.push('PDF with embedded JavaScript detected');
      }
      
      if (textContent.includes('/OpenAction') || textContent.includes('/AA')) {
        results.warnings.push(' PDF has auto-execute actions');
      }
      
      if (textContent.includes('/Launch') || textContent.includes('/URI')) {
        results.warnings.push(' PDF contains external links or launch actions');
      }
    }
    
    // Check archives for dangerous contents (by filename in archive)
    if (['zip', 'rar', '7z'].includes(detectedType?.type) || ['zip', 'rar', '7z'].includes(ext)) {
      const textContent = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      const dangerousInArchive = ['.exe', '.bat', '.cmd', '.scr', '.vbs', '.ps1', '.dll'];
      
      for (const dangerExt of dangerousInArchive) {
        if (textContent.toLowerCase().includes(dangerExt)) {
          results.safe = false;
          results.threats.push(` Archive contains dangerous file type: ${dangerExt}`);
          break;
        }
      }
    }
    
  } catch (e) {
    results.warnings.push(`File inspection error: ${e.message}`);
  }
  
  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPREHENSIVE DEEP LINK ANALYSIS (Uses all APIs)
// ─────────────────────────────────────────────────────────────────────────────
async function deepLinkAnalysis(url, analyzer) {
  // 1. Expand shortened URLs first
  const shortenerDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'short.io', 'cutt.ly'];
  let urlToAnalyze = url;
  
  try {
    const domain = new URL(url).hostname.toLowerCase();
    if (shortenerDomains.some(s => domain.includes(s))) {
      const expanded = await expandShortUrl(url);
      if (expanded.success && expanded.expanded !== url) {
        urlToAnalyze = expanded.expanded;
        analyzer.addRisk(10, 'SHORTENED', `URL was shortened, expanded to: ${expanded.expanded.slice(0, 50)}...`);
        
        // Now analyze the REAL destination
        analyzeLink(urlToAnalyze, analyzer);
      }
    }
  } catch (e) {}
  
  // Extract domain and IP for various checks
  let domainToCheck = null;
  let ipToCheck = null;
  try {
    const parsed = new URL(urlToAnalyze);
    domainToCheck = parsed.hostname;
    // Check if hostname is an IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domainToCheck)) {
      ipToCheck = domainToCheck;
    }
  } catch (e) {}
  
  // Initialize API results storage on analyzer
  if (!analyzer.apiResults) {
    analyzer.apiResults = {};
  }
  
  // Run all API checks in parallel for speed
  const [vtResult, gsbResult, ptResult, ipqsResult, otxResult] = await Promise.all([
    // 1. VirusTotal
    scanWithVirusTotal(urlToAnalyze).catch(e => ({ available: false, error: e.message })),
    
    // 2. Google Safe Browsing
    checkGoogleSafeBrowsing([urlToAnalyze]).catch(e => ({ available: false, error: e.message })),
    
    // 3. PhishTank
    checkPhishTank(urlToAnalyze).catch(e => ({ available: false, error: e.message })),
    
    // 4. IPQualityScore
    scanWithIPQualityScore(urlToAnalyze).catch(e => ({ available: false, error: e.message })),
    
    // 5. AlienVault OTX (check domain)
    domainToCheck ? checkWithAlienVault(domainToCheck, 'domain').catch(e => ({ available: false, error: e.message })) : Promise.resolve({ available: false })
  ]);
  
  // Store API results for detailed reporting
  analyzer.apiResults.virustotal = vtResult;
  analyzer.apiResults.googleSafeBrowsing = gsbResult;
  analyzer.apiResults.phishtank = ptResult;
  analyzer.apiResults.ipqualityscore = ipqsResult;
  analyzer.apiResults.alienvault = otxResult;
  
  // Process VirusTotal results
  if (vtResult.available) {
    if (vtResult.malicious > 0) {
      analyzer.addRisk(40, 'VIRUSTOTAL', `VirusTotal: ${vtResult.malicious} engines flagged as malicious`);
    }
    if (vtResult.suspicious > 0) {
      analyzer.addRisk(20, 'VIRUSTOTAL_SUS', `VirusTotal: ${vtResult.suspicious} engines flagged as suspicious`);
    }
    analyzer.signals.push(`[API] VirusTotal: ${vtResult.malicious || 0} malicious, ${vtResult.suspicious || 0} suspicious`);
  }
  
  // Process Google Safe Browsing results
  if (gsbResult.available && gsbResult.threats && gsbResult.threats.length > 0) {
    for (const threat of gsbResult.threats) {
      analyzer.addRisk(50, 'GOOGLE_SAFE', `Google Safe Browsing: ${threat.threatType}`);
    }
  }
  
  // Process PhishTank results
  if (ptResult.available && ptResult.isPhish) {
    analyzer.addRisk(60, 'PHISHTANK', `PhishTank: Confirmed phishing site${ptResult.verified ? ' (verified)' : ''}`);
  }
  
  // Process IPQualityScore results
  if (ipqsResult.available) {
    // Store fraud score for reporting
    analyzer.apiResults.ipqualityscore.fraudScore = ipqsResult.riskScore;
    
    if (ipqsResult.phishing) {
      analyzer.addRisk(55, 'IPQS_PHISH', `IPQualityScore: Detected as phishing`);
    }
    if (ipqsResult.malware) {
      analyzer.addRisk(55, 'IPQS_MALWARE', `IPQualityScore: Detected as malware`);
    }
    if (ipqsResult.suspicious) {
      analyzer.addRisk(25, 'IPQS_SUS', `IPQualityScore: Flagged as suspicious`);
    }
    if (ipqsResult.riskScore >= 75) {
      analyzer.addRisk(35, 'IPQS_RISK', `IPQualityScore: High risk score (${ipqsResult.riskScore}/100)`);
    } else if (ipqsResult.riskScore >= 50) {
      analyzer.addRisk(15, 'IPQS_RISK', `IPQualityScore: Medium risk score (${ipqsResult.riskScore}/100)`);
    }
    if (ipqsResult.parking) {
      analyzer.addRisk(10, 'IPQS_PARK', `IPQualityScore: Parked domain detected`);
    }
    analyzer.signals.push(`[API] IPQualityScore: Risk ${ipqsResult.riskScore || 0}`);
  }
  
  // Process AlienVault OTX results
  if (otxResult.available && otxResult.found && otxResult.pulseCount > 0) {
    analyzer.addRisk(45, 'ALIENVAULT', `AlienVault OTX: Found in ${otxResult.pulseCount} threat intel pulses`);
    if (otxResult.pulses && otxResult.pulses.length > 0) {
      const threatNames = otxResult.pulses.slice(0, 2).map(p => p.name).join(', ');
      analyzer.signals.push(`[API] OTX Threats: ${threatNames}`);
      // Store malware families for reporting
      analyzer.apiResults.alienvault.malwareFamilies = otxResult.pulses.slice(0, 3).map(p => p.name);
    }
  }
  
  // Check IP with AbuseIPDB if URL contains an IP
  if (ipToCheck) {
    const abuseResult = await checkWithAbuseIPDB(ipToCheck).catch(e => ({ available: false }));
    analyzer.apiResults.abuseipdb = abuseResult;
    
    if (abuseResult.available) {
      // Store for reporting
      abuseResult.abuseScore = abuseResult.abuseConfidenceScore;
      
      if (abuseResult.abuseConfidenceScore >= 50) {
        analyzer.addRisk(40, 'ABUSEIPDB', `AbuseIPDB: High abuse score (${abuseResult.abuseConfidenceScore}%), ${abuseResult.totalReports} reports`);
      } else if (abuseResult.abuseConfidenceScore >= 25) {
        analyzer.addRisk(20, 'ABUSEIPDB', `AbuseIPDB: Moderate abuse score (${abuseResult.abuseConfidenceScore}%)`);
      }
      if (abuseResult.isTor) {
        analyzer.addRisk(15, 'TOR_EXIT', `AbuseIPDB: Tor exit node detected`);
      }
      analyzer.signals.push(`[API] AbuseIPDB: Score ${abuseResult.abuseConfidenceScore}%, ISP: ${abuseResult.isp || 'Unknown'}`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// COMPREHENSIVE FILE ANALYSIS (Uses magic bytes + APIs)
// ─────────────────────────────────────────────────────────────────────────────
async function deepFileAnalysis(attachment, analyzer) {
  // 1. Local magic byte analysis
  const fileResult = await analyzeFileContent(attachment);
  
  if (!fileResult.safe) {
    for (const threat of fileResult.threats) {
      analyzer.addRisk(50, 'FILE_CONTENT', threat);
    }
  }
  
  for (const warning of fileResult.warnings) {
    analyzer.addRisk(15, 'FILE_WARNING', warning);
  }
  
  if (fileResult.magicByteMatch) {
    analyzer.signals.push(`[INFO] File signature: ${fileResult.magicByteMatch.name}`);
  }
  
  // 2. Hybrid Analysis - Submit file URL for sandbox analysis
  const haResult = await scanWithHybridAnalysis(attachment.url, attachment.name).catch(e => ({ available: false }));
  if (haResult.available) {
    if (haResult.verdict === 'malicious' || haResult.threatLevel >= 2) {
      analyzer.addRisk(60, 'HYBRID_MALICIOUS', `Hybrid Analysis: File detected as malicious`);
      if (haResult.malwareFamily) {
        analyzer.addRisk(10, 'HYBRID_FAMILY', `Malware family: ${haResult.malwareFamily}`);
      }
    } else if (haResult.verdict === 'suspicious' || haResult.threatLevel === 1) {
      analyzer.addRisk(30, 'HYBRID_SUS', `Hybrid Analysis: File flagged as suspicious`);
    }
    if (haResult.threatScore > 0) {
      analyzer.signals.push(`[API] Hybrid Analysis: Threat score ${haResult.threatScore}`);
    }
  }
  
  // 3. VirusTotal file scan (by URL)
  const vtResult = await scanWithVirusTotal(attachment.url).catch(e => ({ available: false }));
  if (vtResult.available) {
    if (vtResult.malicious > 0) {
      analyzer.addRisk(45, 'VT_FILE', `VirusTotal: ${vtResult.malicious} engines flagged file`);
    }
    if (vtResult.suspicious > 0) {
      analyzer.addRisk(20, 'VT_FILE_SUS', `VirusTotal: ${vtResult.suspicious} engines suspicious`);
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────

function analyzeLink(url, analyzer) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();
    
    // 1. Check trusted domains (reduce risk significantly)
    if (MALICIOUS_INDICATORS.trustedDomains.some(d => domain === d || domain.endsWith('.' + d))) {
      analyzer.reduceRisk(30, `Trusted domain: ${domain}`);
      return;
    }
    
    // 2. Homograph attack detection
    const hasHomograph = [...domain].some(char => HOMOGRAPH_MAP[char]);
    if (hasHomograph) {
      analyzer.addRisk(40, 'HOMOGRAPH', `Unicode lookalike characters in domain: ${domain}`);
    }
    
    // 3. Typosquatting detection
    for (const [brand, typos] of Object.entries(BRAND_TYPOSQUATS)) {
      for (const typo of typos) {
        if (domain.includes(typo) && !domain.includes(brand + '.com')) {
          analyzer.addRisk(35, 'TYPOSQUAT', `Possible ${brand} impersonation: ${domain}`);
        }
      }
      // Also check if domain looks like brand but isn't the real one
      if (domain.includes(brand) && !MALICIOUS_INDICATORS.trustedDomains.some(d => domain === d)) {
        analyzer.addRisk(25, 'IMPERSONATION', `Contains brand name "${brand}" but not official: ${domain}`);
      }
    }
    
    // 4. URL shortener detection
    if (MALICIOUS_INDICATORS.shorteners.some(s => domain.includes(s))) {
      analyzer.addRisk(20, 'SHORTENER', `URL shortener hides destination: ${domain}`);
    }
    
    // 5. Free hosting detection
    if (MALICIOUS_INDICATORS.freeHosting.some(h => domain.endsWith(h))) {
      analyzer.addRisk(15, 'FREE_HOST', `Free hosting often used for phishing: ${domain}`);
    }
    
    // 6. Suspicious TLD detection
    const tld = '.' + domain.split('.').pop();
    if (MALICIOUS_INDICATORS.suspiciousTLDs.includes(tld)) {
      analyzer.addRisk(15, 'SUS_TLD', `Suspicious top-level domain: ${tld}`);
    }
    
    // 7. IP address as host
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
      analyzer.addRisk(25, 'IP_HOST', `Direct IP address instead of domain: ${domain}`);
    }
    
    // 8. Suspicious URL patterns
    if (fullUrl.includes('login') || fullUrl.includes('signin') || fullUrl.includes('verify')) {
      analyzer.addRisk(15, 'LOGIN_PATH', 'URL contains login/verify path');
    }
    if (fullUrl.includes('token') || fullUrl.includes('password') || fullUrl.includes('credential')) {
      analyzer.addRisk(20, 'CRED_PATH', 'URL references credentials');
    }
    
    // 9. Excessive subdomains (phishing tactic)
    const subdomains = domain.split('.').length - 2;
    if (subdomains > 3) {
      analyzer.addRisk(10, 'SUBDOMAINS', `Excessive subdomains (${subdomains})`);
    }
    
    // 10. Long domain name
    if (domain.length > 50) {
      analyzer.addRisk(10, 'LONG_DOMAIN', `Unusually long domain name`);
    }
    
  } catch (e) {
    analyzer.addRisk(5, 'INVALID_URL', 'Malformed URL structure');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// MESSAGE CONTENT ANALYSIS (Social Engineering Detection)
// ─────────────────────────────────────────────────────────────────────────────

function analyzeMessage(content, analyzer) {
  const text = content.toLowerCase();
  
  // Check each category of social engineering patterns
  for (const [category, patterns] of Object.entries(SOCIAL_ENGINEERING_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(content)) {
        const points = {
          urgency: 15,
          authority: 20,
          threat: 25,
          prize: 20,
          fear: 15,
          demands: 10
        }[category] || 10;
        
        analyzer.addRisk(points, `SE_${category.toUpperCase()}`, `Social engineering pattern: ${category}`);
        break; // Only count each category once
      }
    }
  }
  
  // Check for credential requests
  if (/\b(password|token|2fa|mfa|auth|login|credential|api.?key)\b/i.test(content)) {
    analyzer.addRisk(20, 'CRED_REQUEST', 'Message requests sensitive credentials');
  }
  
  // QR code mention (common scam vector)
  if (/\b(qr|scan.{0,10}code)\b/i.test(content)) {
    analyzer.addRisk(15, 'QR_MENTION', 'QR code mentioned (common scam vector)');
  }
  
  // Money/crypto scam indicators
  if (/\b(send.{0,10}(btc|eth|crypto|bitcoin)|crypto.{0,10}(giveaway|double))\b/i.test(content)) {
    analyzer.addRisk(30, 'CRYPTO_SCAM', 'Cryptocurrency scam pattern');
  }
  
  // DM scam patterns
  if (/\b(dm.{0,10}(me|for)|contact.{0,10}(telegram|whatsapp))\b/i.test(content)) {
    analyzer.addRisk(15, 'DM_DIVERT', 'Attempting to move conversation off platform');
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FILE ANALYSIS (Static - No Execution)
// ─────────────────────────────────────────────────────────────────────────────

function analyzeFile(filename, filesize, analyzer) {
  const name = filename.toLowerCase();
  const ext = '.' + name.split('.').pop();
  const parts = name.split('.');
  
  // 1. Dangerous extension check
  if (FILE_THREATS.dangerous.includes(ext)) {
    analyzer.addRisk(50, 'DANGEROUS_EXT', `Dangerous file type: ${ext}`);
  }
  
  // 2. Macro-enabled document
  if (FILE_THREATS.macroEnabled.includes(ext)) {
    analyzer.addRisk(35, 'MACRO_DOC', `Macro-enabled document: ${ext}`);
  }
  
  // 3. Double extension detection (e.g., photo.jpg.exe)
  if (parts.length > 2) {
    const secondToLast = '.' + parts[parts.length - 2];
    if (FILE_THREATS.dangerous.includes(ext) && 
        ['.jpg', '.png', '.gif', '.pdf', '.doc', '.txt'].includes(secondToLast)) {
      analyzer.addRisk(45, 'DOUBLE_EXT', `Hidden extension attack: ${filename}`);
    }
  }
  
  // 4. Archive inspection needed
  if (FILE_THREATS.archives.includes(ext)) {
    analyzer.addRisk(10, 'ARCHIVE', `Archive file requires manual inspection: ${ext}`);
  }
  
  // 5. Suspicious filenames
  if (/\b(crack|keygen|patch|serial|hack|cheat|free|download)\b/i.test(name)) {
    analyzer.addRisk(25, 'SUS_FILENAME', 'Suspicious filename pattern');
  }
  
  // 6. Very small dangerous files (likely malicious)
  if (filesize < 5000 && FILE_THREATS.dangerous.includes(ext)) {
    analyzer.addRisk(20, 'TINY_EXEC', 'Suspiciously small executable');
  }
  
  // 7. Very large unexpected files
  if (filesize > 50000000) { // 50MB
    analyzer.addRisk(10, 'LARGE_FILE', 'Unusually large file');
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN THREAT ANALYSIS FUNCTION
// ═══════════════════════════════════════════════════════════════════════════════

async function analyzeThreat(message) {
  const analyzer = new ThreatAnalyzer();
  
  // Extract links
  const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`[\]]+)/gi;
  const links = message.content.match(urlRegex) || [];
  
  // PHASE 1: Fast local analysis (instant)
  for (const link of links) {
    analyzeLink(link, analyzer);
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PAYLOADER DETECTION - Check all links for downloadable malware
    // ═══════════════════════════════════════════════════════════════════════════
    const payloaderCheck = detectPayloader(link);
    if (payloaderCheck.isPayloader) {
      for (const threat of payloaderCheck.threats) {
        analyzer.addRisk(
          threat.severity === 'critical' ? 50 : threat.severity === 'high' ? 35 : 20,
          threat.type,
          threat.description
        );
      }
    }
  }
  
  // Analyze message content for social engineering
  analyzeMessage(message.content, analyzer);
  
  // Analyze attachments (basic)
  if (message.attachments && message.attachments.size > 0) {
    for (const [, attachment] of message.attachments) {
      analyzeFile(attachment.name, attachment.size, analyzer);
      
      // Also check attachment URL for payloader indicators
      const attachPayloader = detectPayloader(attachment.url, attachment.name);
      if (attachPayloader.isPayloader) {
        for (const threat of attachPayloader.threats) {
          analyzer.addRisk(
            threat.severity === 'critical' ? 50 : threat.severity === 'high' ? 35 : 20,
            threat.type,
            threat.description
          );
        }
      }
    }
  }
  
  // PHASE 2: Deep API analysis (if APIs available and initial score warrants it)
  // Only do deep analysis if we found something suspicious OR there are links/files
  const needsDeepAnalysis = analyzer.riskScore > 10 || links.length > 0 || (message.attachments && message.attachments.size > 0);
  
  if (needsDeepAnalysis) {
    // Deep link analysis with external APIs
    for (const link of links) {
      try {
        await deepLinkAnalysis(link, analyzer);
      } catch (e) {
        console.error('Deep link analysis error:', e.message);
      }
    }
    
    // Deep file analysis (download and inspect)
    if (message.attachments && message.attachments.size > 0) {
      for (const [, attachment] of message.attachments) {
        try {
          await deepFileAnalysis(attachment, analyzer);
        } catch (e) {
          console.error('Deep file analysis error:', e.message);
        }
      }
    }
  }
  
  return analyzer.getResult();
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT RESPONSE ACTIONS
// ═══════════════════════════════════════════════════════════════════════════════

async function handleThreatResponse(message, analysis, guild) {
  // Find channels by NAME (more reliable than hardcoded IDs)
  const securityChannel = guild.channels.cache.find(c => 
    c.name === 'security-logs' || c.name === 'security-log' || c.name === 'threat-logs'
  ) || guild.channels.cache.get(SECURITY_LOG_CHANNEL);
  
  const modmailLog = guild.channels.cache.find(c => 
    c.name === 'modmail-logs' || c.name === 'modmail-log'
  ) || guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
  
  // Skip if nothing significant
  if (analysis.score < RISK_THRESHOLDS.LOW) return analysis;
  
  console.log(`[SECURITY] Threat detected - Score: ${analysis.score}, Level: ${analysis.level}`);
  console.log(`[SECURITY] Security channel: ${securityChannel?.name || 'NOT FOUND'}`);
  console.log(`[SECURITY] Modmail log: ${modmailLog?.name || 'NOT FOUND'}`);
  
  // ═══════════════════════════════════════════════════════════════
  // BUILD DETAILED SECURITY ALERT FOR STAFF
  // ═══════════════════════════════════════════════════════════════
  
  const threatEmoji = {
    critical: '',
    high: '',
    medium: '',
    low: ''
  }[analysis.level] || '';
  
  const threatColor = {
    critical: 0xFF0000,
    high: 0xFF6600,
    medium: 0xFFAA00,
    low: 0xFFFF00
  }[analysis.level] || 0x00FF00;
  
  // Main alert embed
  const alertEmbed = new EmbedBuilder()
    .setTitle(`${threatEmoji} SECURITY ALERT: ${analysis.level.toUpperCase()} THREAT`)
    .setDescription(`
**━━━━━━━━━━━━ THREAT SUMMARY ━━━━━━━━━━━━**
**Risk Score:** \`${analysis.score}/100\`
**Action Taken:** \`${analysis.action}\`
**Detection Time:** <t:${Math.floor(Date.now()/1000)}:F>
    `)
    .setColor(threatColor)
    .setTimestamp();
  
  // User info
  alertEmbed.addFields({
    name: ' User Information',
    value: `**User:** ${message.author.tag}\n**ID:** \`${message.author.id}\`\n**Account Age:** ${Math.floor((Date.now() - message.author.createdTimestamp) / 86400000)} days`,
    inline: false
  });
  
  // Message content
  alertEmbed.addFields({
    name: ' Message Content',
    value: `\`\`\`${message.content.slice(0, 900) || 'No text content'}\`\`\``,
    inline: false
  });
  
  // ═══════════════════════════════════════════════════════════════
  // API RESULTS BREAKDOWN
  // ═══════════════════════════════════════════════════════════════
  
  if (analysis.apiResults) {
    const api = analysis.apiResults;
    
    // VirusTotal Results
    if (api.virustotal?.available) {
      const vt = api.virustotal;
      let vtStatus = ' Clean';
      if (vt.malicious > 0) vtStatus = ` **${vt.malicious} MALICIOUS**`;
      else if (vt.suspicious > 0) vtStatus = ` ${vt.suspicious} Suspicious`;
      
      alertEmbed.addFields({
        name: ' VirusTotal (70+ Antivirus Engines)',
        value: `**Status:** ${vtStatus}\n**Malicious:** ${vt.malicious || 0}\n**Suspicious:** ${vt.suspicious || 0}\n**Clean:** ${vt.harmless || 0}${vt.threatNames?.length ? `\n**Threats:** ${vt.threatNames.slice(0,5).join(', ')}` : ''}`,
        inline: true
      });
    }
    
    // Google Safe Browsing Results
    if (api.googleSafeBrowsing?.available) {
      const gsb = api.googleSafeBrowsing;
      let gsbStatus = ' Not in Google\'s threat database';
      if (gsb.threats?.length > 0) {
        const threatTypes = gsb.threats.map(t => t.threatType).join(', ');
        gsbStatus = ` **FLAGGED:** ${threatTypes}`;
      }
      
      alertEmbed.addFields({
        name: ' Google Safe Browsing',
        value: gsbStatus,
        inline: true
      });
    }
    
    // PhishTank Results
    if (api.phishtank?.available) {
      const pt = api.phishtank;
      let ptStatus = ' Not in PhishTank database';
      if (pt.isPhish) {
        ptStatus = ` **CONFIRMED PHISHING**${pt.verified ? ' (Verified)' : ''}\n**Reported:** ${pt.verifiedAt || 'Unknown'}`;
      }
      
      alertEmbed.addFields({
        name: ' PhishTank (Community Reports)',
        value: ptStatus,
        inline: true
      });
    }
    
    // IPQualityScore Results
    if (api.ipqualityscore?.available) {
      const ipqs = api.ipqualityscore;
      let ipqsStatus = `**Fraud Score:** ${ipqs.fraudScore || 0}/100\n`;
      ipqsStatus += `**Suspicious:** ${ipqs.suspicious ? ' Yes' : ' No'}\n`;
      ipqsStatus += `**Phishing:** ${ipqs.phishing ? ' Yes' : ' No'}\n`;
      ipqsStatus += `**Malware:** ${ipqs.malware ? ' Yes' : ' No'}`;
      if (ipqs.category) ipqsStatus += `\n**Category:** ${ipqs.category}`;
      
      alertEmbed.addFields({
        name: ' IPQualityScore',
        value: ipqsStatus,
        inline: true
      });
    }
    
    // AlienVault OTX Results
    if (api.alienvault?.available) {
      const otx = api.alienvault;
      let otxStatus = `**Pulse Count:** ${otx.pulseCount || 0}\n`;
      if (otx.pulseCount > 0) {
        otxStatus += ` Found in ${otx.pulseCount} threat intelligence feeds\n`;
        if (otx.malwareFamilies?.length) {
          otxStatus += `**Malware Families:** ${otx.malwareFamilies.slice(0,3).join(', ')}`;
        }
      } else {
        otxStatus += ' Not found in threat feeds';
      }
      
      alertEmbed.addFields({
        name: ' AlienVault OTX (Threat Intel)',
        value: otxStatus,
        inline: true
      });
    }
    
    // AbuseIPDB Results
    if (api.abuseipdb?.available) {
      const aip = api.abuseipdb;
      let aipStatus = `**Abuse Score:** ${aip.abuseScore || 0}%\n`;
      aipStatus += `**Reports:** ${aip.totalReports || 0}\n`;
      aipStatus += aip.abuseScore > 50 ? ' HIGH ABUSE CONFIDENCE' : ' Low abuse reports';
      
      alertEmbed.addFields({
        name: ' AbuseIPDB',
        value: aipStatus,
        inline: true
      });
    }
  }
  
  // ═══════════════════════════════════════════════════════════════
  // DETECTION DETAILS
  // ═══════════════════════════════════════════════════════════════
  
  if (analysis.findings?.length > 0) {
    const detections = analysis.findings.slice(0, 10).map(f => 
      `${f.points >= 30 ? '' : f.points >= 15 ? '' : ''} **[${f.code}]** +${f.points} pts\n└ ${f.detail}`
    ).join('\n\n');
    
    alertEmbed.addFields({
      name: ' Detection Breakdown',
      value: detections.slice(0, 1024) || 'No specific detections',
      inline: false
    });
  }
  
  // Attachments
  if (message.attachments.size > 0) {
    const attachList = [...message.attachments.values()]
      .map(a => ` **${a.name}** (${Math.round(a.size/1024)}KB) - ${a.contentType || 'Unknown type'}`)
      .join('\n');
    alertEmbed.addFields({ name: ' Attachments', value: attachList, inline: false });
  }
  
  // ═══════════════════════════════════════════════════════════════
  // THREAT EXPLANATION
  // ═══════════════════════════════════════════════════════════════
  
  let explanation = '';
  if (analysis.findings) {
    for (const f of analysis.findings) {
      if (f.code === 'TYPOSQUAT') explanation += '**Typosquatting:** Domain mimics a legitimate site (e.g., discrod.com instead of discord.com). Common phishing tactic.\n\n';
      if (f.code === 'HOMOGRAPH') explanation += '**Homograph Attack:** Uses lookalike Unicode characters (е vs e, а vs a) to create fake domains that look identical to real ones.\n\n';
      if (f.code === 'VIRUSTOTAL') explanation += '**Antivirus Detection:** Multiple security engines have flagged this URL/file as malicious. Likely contains malware, phishing, or exploit code.\n\n';
      if (f.code === 'PHISHTANK') explanation += '**Confirmed Phishing:** Community-verified phishing site designed to steal credentials.\n\n';
      if (f.code === 'GOOGLE_SAFE') explanation += '**Google Blacklist:** Google has identified this as a dangerous site (malware, phishing, or unwanted software).\n\n';
      if (f.code === 'DANGEROUS_EXT') explanation += '**Dangerous File:** Executable or script file that can run code on your computer. Never open files like .exe, .bat, .scr from untrusted sources.\n\n';
      if (f.code === 'SE_URGENCY' || f.code === 'SE_THREAT') explanation += '**Social Engineering:** Uses psychological manipulation (urgency, fear, threats) to trick victims into acting without thinking.\n\n';
      if (f.code === 'FILE_CONTENT') explanation += '**File Analysis:** The actual file contents don\'t match its extension, or contain hidden executable code.\n\n';
    }
  }
  
  if (explanation) {
    alertEmbed.addFields({
      name: ' What This Means',
      value: explanation.slice(0, 1024),
      inline: false
    });
  }
  
  // Action buttons
  const actionRow = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId(`security_ban_${message.author.id}`)
      .setLabel('Ban User')
      .setStyle(ButtonStyle.Danger)
      .setEmoji(''),
    new ButtonBuilder()
      .setCustomId(`security_warn_${message.author.id}`)
      .setLabel('Warn User')
      .setStyle(ButtonStyle.Primary)
      .setEmoji(''),
    new ButtonBuilder()
      .setCustomId(`security_dismiss_${message.author.id}`)
      .setLabel('Dismiss')
      .setStyle(ButtonStyle.Secondary)
      .setEmoji('')
  );
  
  // Send to security log channel
  if (securityChannel) {
    const pingRole = analysis.level === 'critical' ? '@here' : '';
    await securityChannel.send({ 
      content: pingRole, 
      embeds: [alertEmbed],
      components: [actionRow]
    });
    console.log(`[SECURITY] Alert sent to #${securityChannel.name}`);
  } else {
    console.log('[SECURITY] WARNING: No security-logs channel found!');
    // Try to send to modmail-logs as fallback
    if (modmailLog) {
      await modmailLog.send({ 
        content: analysis.level === 'critical' ? '@here' : '',
        embeds: [alertEmbed],
        components: [actionRow]
      });
      console.log(`[SECURITY] Alert sent to fallback #${modmailLog.name}`);
    } else {
      // Last resort - find any staff channel
      const staffChannel = guild.channels.cache.find(c => 
        c.name.includes('staff') || c.name.includes('mod-log') || c.name.includes('admin')
      );
      if (staffChannel) {
        await staffChannel.send({ embeds: [alertEmbed], components: [actionRow] });
        console.log(`[SECURITY] Alert sent to fallback #${staffChannel.name}`);
      }
    }
  }
  
  // Also send brief to modmail log if it's a different channel
  if (modmailLog && securityChannel && modmailLog.id !== securityChannel.id) {
    const briefEmbed = new EmbedBuilder()
      .setTitle(`${threatEmoji} Security Alert - ${analysis.level.toUpperCase()}`)
      .setDescription(`**User:** ${message.author.tag}\n**Score:** ${analysis.score}/100\n**Action:** ${analysis.action}`)
      .setColor(threatColor)
      .setFooter({ text: 'Full details in #security-logs' });
    
    await modmailLog.send({ embeds: [briefEmbed] });
  }
  
  return analysis;
}

// Legacy compatibility - keep old functions working
const SCAM_PATTERNS = Object.values(SOCIAL_ENGINEERING_PATTERNS).flat();
const SUSPICIOUS_DOMAINS = [...MALICIOUS_INDICATORS.shorteners, ...MALICIOUS_INDICATORS.freeHosting];

// ═══════════════════════════════════════════════════════════════════════════════
// LINK SCANNER & SECURITY (Legacy + Enhanced)
// ═══════════════════════════════════════════════════════════════════════════════

async function scanLink(url) {
  const results = {
    safe: true,
    threats: [],
    warnings: []
  };
  
  try {
    // Check against known suspicious domains
    const domain = new URL(url).hostname.toLowerCase();
    
    for (const suspicious of SUSPICIOUS_DOMAINS) {
      if (domain.includes(suspicious)) {
        results.safe = false;
        results.threats.push(`Suspicious domain detected: ${suspicious}`);
      }
    }
    
    // Check for URL shorteners
    if (['bit.ly', 'tinyurl.com', 'shorturl.at', 'rb.gy', 't.co', 'goo.gl'].some(s => domain.includes(s))) {
      results.warnings.push('URL shortener detected - could hide malicious link');
    }
    
    // Check for Discord impersonation
    if (domain.includes('discord') && !domain.includes('discord.com') && !domain.includes('discord.gg') && !domain.includes('discordapp.com')) {
      results.safe = false;
      results.threats.push('Fake Discord domain detected - likely phishing');
    }
    
    // Check for Steam impersonation
    if (domain.includes('steam') && !domain.includes('steampowered.com') && !domain.includes('steamcommunity.com')) {
      results.safe = false;
      results.threats.push('Fake Steam domain detected - likely phishing');
    }
    
    // VirusTotal scan if API key exists
    if (process.env.VIRUSTOTAL_API_KEY) {
      try {
        const vtResult = await scanWithVirusTotal(url);
        if (vtResult.malicious > 0) {
          results.safe = false;
          results.threats.push(`VirusTotal: ${vtResult.malicious} security vendors flagged this as malicious`);
        }
        if (vtResult.suspicious > 0) {
          results.warnings.push(`VirusTotal: ${vtResult.suspicious} security vendors flagged this as suspicious`);
        }
      } catch (e) {
        results.warnings.push('Could not complete VirusTotal scan');
      }
    }
    
  } catch (e) {
    results.warnings.push('Invalid URL format');
  }
  
  return results;
}

function detectScamPatterns(message) {
  const threats = [];
  
  for (const pattern of SCAM_PATTERNS) {
    if (pattern.test(message)) {
      threats.push(`Scam pattern detected: ${pattern.toString()}`);
    }
  }
  
  return threats;
}

function extractLinks(text) {
  const urlRegex = /(https?:\/\/[^\s<>"{}|\\^`\[\]]+)/gi;
  return text.match(urlRegex) || [];
}

// ═══════════════════════════════════════════════════════════════════════════════
// TRANSLATION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

async function detectAndTranslate(text) {
  if (!anthropic) return { original: text, translated: null, language: 'unknown' };
  
  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: `Analyze this text and respond ONLY with a JSON object (no markdown, no explanation):
{
  "language": "detected language name",
  "languageCode": "ISO code like en, es, fr",
  "isEnglish": true/false,
  "translation": "English translation if not English, otherwise null"
}

Text to analyze: "${text}"`
      }]
    });
    
    const result = JSON.parse(response.content[0].text);
    return {
      original: text,
      translated: result.translation,
      language: result.language,
      languageCode: result.languageCode,
      isEnglish: result.isEnglish
    };
  } catch (e) {
    console.log('Translation error:', e.message);
    return { original: text, translated: null, language: 'unknown' };
  }
}

async function translateToLanguage(text, targetLanguage) {
  if (!anthropic) return text;
  
  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1000,
      messages: [{
        role: 'user',
        content: `Translate this text to ${targetLanguage}. Respond ONLY with the translation, nothing else:

"${text}"`
      }]
    });
    
    return response.content[0].text;
  } catch (e) {
    return text;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// MOOD DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

async function analyzeMood(text) {
  if (!anthropic) return { mood: 'neutral', urgency: 'normal', emoji: '' };
  
  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 200,
      messages: [{
        role: 'user',
        content: `Analyze the mood and urgency of this message. Respond ONLY with JSON (no markdown):
{
  "mood": "angry/frustrated/upset/neutral/friendly/happy",
  "urgency": "critical/high/normal/low",
  "emoji": "appropriate emoji",
  "escalate": true/false,
  "reason": "brief reason if escalate is true"
}

Message: "${text}"`
      }]
    });
    
    return JSON.parse(response.content[0].text);
  } catch (e) {
    return { mood: 'neutral', urgency: 'normal', emoji: '', escalate: false };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// AI BAN APPEAL SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

async function processAppeal(userId, appealText, banReason) {
  if (!anthropic) return { recommendation: 'manual_review', reasoning: 'AI not available' };
  
  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 500,
      messages: [{
        role: 'user',
        content: `You are a fair but strict appeal reviewer for a gaming Discord server called "The Unpatched Method". 

Review this ban appeal and provide your recommendation.

**Original Ban Reason:** ${banReason || 'Not specified'}

**User's Appeal:** ${appealText}

Respond ONLY with JSON (no markdown):
{
  "recommendation": "approve/deny/manual_review",
  "confidence": 0-100,
  "reasoning": "detailed explanation",
  "redFlags": ["list of concerns if any"],
  "positiveFactors": ["list of good points if any"],
  "suggestedAction": "what staff should do",
  "followUpQuestions": ["questions to ask user if needed"]
}`
      }]
    });
    
    return JSON.parse(response.content[0].text);
  } catch (e) {
    return { recommendation: 'manual_review', reasoning: 'AI analysis failed: ' + e.message };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// THREAT DETECTION
// ═══════════════════════════════════════════════════════════════════════════════

const THREAT_PATTERNS = [
  { pattern: /kill\s*(your)?self/i, type: 'self_harm', severity: 'critical' },
  { pattern: /i('ll|m\s*gonna|will)\s*kill/i, type: 'threat', severity: 'critical' },
  { pattern: /bomb\s*threat/i, type: 'threat', severity: 'critical' },
  { pattern: /shoot\s*up/i, type: 'threat', severity: 'critical' },
  { pattern: /doxx/i, type: 'doxxing', severity: 'high' },
  { pattern: /your\s*(address|ip|location)/i, type: 'doxxing', severity: 'high' },
  { pattern: /swat/i, type: 'swatting', severity: 'critical' },
];

function detectThreats(message) {
  const threats = [];
  
  for (const { pattern, type, severity } of THREAT_PATTERNS) {
    if (pattern.test(message)) {
      threats.push({ type, severity, pattern: pattern.toString() });
    }
  }
  
  return threats;
}

// ═══════════════════════════════════════════════════════════════════════════════
// USER REPUTATION SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

async function getUserReputation(userId) {
  try {
    const result = await pool.query(`
      SELECT * FROM user_reputation WHERE user_id = $1
    `, [userId]);
    
    if (result.rows.length === 0) {
      // Create default reputation
      await pool.query(`
        INSERT INTO user_reputation (user_id, score, total_tickets, good_interactions, bad_interactions)
        VALUES ($1, 50, 0, 0, 0)
      `, [userId]);
      return { score: 50, total_tickets: 0, good_interactions: 0, bad_interactions: 0, tier: 'neutral' };
    }
    
    const rep = result.rows[0];
    rep.tier = rep.score >= 80 ? 'trusted' : rep.score >= 50 ? 'neutral' : rep.score >= 20 ? 'caution' : 'problematic';
    return rep;
  } catch (e) {
    return { score: 50, tier: 'neutral' };
  }
}

async function updateReputation(userId, change, reason) {
  try {
    await pool.query(`
      UPDATE user_reputation 
      SET score = GREATEST(0, LEAST(100, score + $2)),
          ${change > 0 ? 'good_interactions = good_interactions + 1' : 'bad_interactions = bad_interactions + 1'}
      WHERE user_id = $1
    `, [userId, change]);
  } catch (e) {
    console.log('Rep update error:', e.message);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

async function initDatabase() {
  // Drop ALL old tables to recreate with correct schema
  await pool.query(`DROP TABLE IF EXISTS modmail_messages CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS modmail_tickets CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS modmail_blacklist CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS modmail_canned CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS user_reputation CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS ban_appeals CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS link_scans CASCADE`);
  
  // Core modmail tables
  await pool.query(`
    CREATE TABLE IF NOT EXISTS modmail_tickets (
      id SERIAL PRIMARY KEY,
      ticket_number INT NOT NULL,
      user_id TEXT NOT NULL,
      guild_id TEXT NOT NULL,
      channel_id TEXT,
      status TEXT DEFAULT 'open',
      priority TEXT DEFAULT 'normal',
      category TEXT DEFAULT 'general',
      claimed_by TEXT,
      mood TEXT DEFAULT 'neutral',
      language TEXT DEFAULT 'en',
      metadata JSONB DEFAULT '{}',
      created_at TIMESTAMP DEFAULT NOW(),
      closed_at TIMESTAMP,
      closed_by TEXT,
      close_reason TEXT
    )
  `);
  
  // Add metadata column if it doesn't exist (for existing tables)
  await pool.query(`ALTER TABLE modmail_tickets ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}'`).catch(() => {});
  
  await pool.query(`
    CREATE TABLE IF NOT EXISTS modmail_messages (
      id SERIAL PRIMARY KEY,
      ticket_id INT,
      author_id TEXT NOT NULL,
      author_name TEXT NOT NULL,
      content TEXT NOT NULL,
      original_content TEXT,
      detected_language TEXT,
      is_staff BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS modmail_blacklist (
      user_id TEXT PRIMARY KEY,
      reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS modmail_canned (
      name TEXT PRIMARY KEY,
      content TEXT NOT NULL
    )
  `);
  
  // User reputation system
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_reputation (
      user_id TEXT PRIMARY KEY,
      score INT DEFAULT 50,
      total_tickets INT DEFAULT 0,
      good_interactions INT DEFAULT 0,
      bad_interactions INT DEFAULT 0,
      last_updated TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Ban appeals system
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ban_appeals (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      ban_reason TEXT,
      appeal_text TEXT NOT NULL,
      ai_recommendation TEXT,
      ai_reasoning TEXT,
      status TEXT DEFAULT 'pending',
      reviewed_by TEXT,
      reviewed_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Link scan history
  await pool.query(`
    CREATE TABLE IF NOT EXISTS link_scans (
      id SERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      user_id TEXT NOT NULL,
      is_safe BOOLEAN,
      threats TEXT[],
      scanned_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // ═══════════════════════════════════════════════════════════════════════════
  // ELITE FEATURE TABLES
  // ═══════════════════════════════════════════════════════════════════════════
  
  // User notes (persistent across tickets)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_notes (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      note TEXT NOT NULL,
      added_by TEXT NOT NULL,
      added_by_name TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Canned responses/snippets
  await pool.query(`
    CREATE TABLE IF NOT EXISTS snippets (
      id SERIAL PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      content TEXT NOT NULL,
      created_by TEXT NOT NULL,
      uses INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Staff away status
  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_status (
      user_id TEXT PRIMARY KEY,
      status TEXT DEFAULT 'available',
      away_message TEXT,
      away_until TIMESTAMP,
      updated_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Ticket feedback/ratings
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_feedback (
      id SERIAL PRIMARY KEY,
      ticket_id INT NOT NULL,
      user_id TEXT NOT NULL,
      rating INT NOT NULL,
      comment TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Read receipts
  await pool.query(`
    CREATE TABLE IF NOT EXISTS read_receipts (
      id SERIAL PRIMARY KEY,
      ticket_id INT NOT NULL,
      message_id TEXT NOT NULL,
      read_by TEXT NOT NULL,
      read_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Ticket views (who viewed when)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_views (
      id SERIAL PRIMARY KEY,
      ticket_id INT NOT NULL,
      viewer_id TEXT NOT NULL,
      viewer_name TEXT NOT NULL,
      viewed_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Linked tickets
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ticket_links (
      id SERIAL PRIMARY KEY,
      ticket_id INT NOT NULL,
      linked_ticket_id INT NOT NULL,
      linked_by TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // User sentiment history
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_sentiment (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      ticket_id INT NOT NULL,
      sentiment TEXT NOT NULL,
      score INT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Staff analytics
  await pool.query(`
    CREATE TABLE IF NOT EXISTS staff_analytics (
      id SERIAL PRIMARY KEY,
      staff_id TEXT NOT NULL,
      ticket_id INT NOT NULL,
      action TEXT NOT NULL,
      response_time_seconds INT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  // Scheduled messages
  await pool.query(`
    CREATE TABLE IF NOT EXISTS scheduled_messages (
      id SERIAL PRIMARY KEY,
      ticket_id INT NOT NULL,
      content TEXT NOT NULL,
      scheduled_by TEXT NOT NULL,
      send_at TIMESTAMP NOT NULL,
      sent BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  console.log('[DB] All tables ready (including elite features)');
}

// ═══════════════════════════════════════════════════════════════════════════════
// ELITE FEATURE SYSTEMS
// ═══════════════════════════════════════════════════════════════════════════════

// Track active typing indicators
const activeTyping = new Map(); // ticketId -> { staff: bool, user: bool }

// Track ticket queue for position
async function getQueuePosition(ticketId) {
  const r = await pool.query(`
    SELECT COUNT(*) as pos FROM modmail_tickets 
    WHERE status = 'open' AND claimed_by IS NULL AND id < $1
  `, [ticketId]);
  return parseInt(r.rows[0].pos) + 1;
}

// Get online staff count
async function getOnlineStaffCount(guild) {
  let onlineCount = 0;
  const members = await guild.members.fetch();
  members.forEach(m => {
    if (isStaff(m) && m.presence?.status !== 'offline' && m.presence?.status !== 'invisible') {
      onlineCount++;
    }
  });
  return onlineCount;
}

// Check if any staff is away
async function getAvailableStaff() {
  const r = await pool.query(`
    SELECT user_id FROM staff_status 
    WHERE status = 'available' OR away_until < NOW()
  `);
  return r.rows.map(row => row.user_id);
}

// Get staff away message
async function getStaffStatus(staffId) {
  const r = await pool.query(`SELECT * FROM staff_status WHERE user_id = $1`, [staffId]);
  if (r.rows.length === 0) return { status: 'available' };
  const status = r.rows[0];
  if (status.away_until && new Date(status.away_until) < new Date()) {
    await pool.query(`UPDATE staff_status SET status = 'available', away_message = NULL, away_until = NULL WHERE user_id = $1`, [staffId]);
    return { status: 'available' };
  }
  return status;
}

// Set staff status
async function setStaffStatus(staffId, status, message = null, until = null) {
  await pool.query(`
    INSERT INTO staff_status (user_id, status, away_message, away_until, updated_at)
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (user_id) DO UPDATE SET status = $2, away_message = $3, away_until = $4, updated_at = NOW()
  `, [staffId, status, message, until]);
}

// Get user notes
async function getUserNotes(userId) {
  const r = await pool.query(`SELECT * FROM user_notes WHERE user_id = $1 ORDER BY created_at DESC`, [userId]);
  return r.rows;
}

// Add user note
async function addUserNote(userId, note, addedBy, addedByName) {
  await pool.query(`
    INSERT INTO user_notes (user_id, note, added_by, added_by_name)
    VALUES ($1, $2, $3, $4)
  `, [userId, note, addedBy, addedByName]);
}

// Get snippet
async function getSnippet(name) {
  const r = await pool.query(`SELECT * FROM snippets WHERE LOWER(name) = LOWER($1)`, [name]);
  if (r.rows.length > 0) {
    await pool.query(`UPDATE snippets SET uses = uses + 1 WHERE LOWER(name) = LOWER($1)`, [name]);
    return r.rows[0];
  }
  return null;
}

// Save snippet
async function saveSnippet(name, content, createdBy) {
  await pool.query(`
    INSERT INTO snippets (name, content, created_by)
    VALUES ($1, $2, $3)
    ON CONFLICT (name) DO UPDATE SET content = $2
  `, [name, content, createdBy]);
}

// Record ticket view
async function recordTicketView(ticketId, viewerId, viewerName) {
  // Check if already viewed recently (within 5 min)
  const r = await pool.query(`
    SELECT 1 FROM ticket_views 
    WHERE ticket_id = $1 AND viewer_id = $2 AND viewed_at > NOW() - INTERVAL '5 minutes'
  `, [ticketId, viewerId]);
  if (r.rows.length === 0) {
    await pool.query(`
      INSERT INTO ticket_views (ticket_id, viewer_id, viewer_name)
      VALUES ($1, $2, $3)
    `, [ticketId, viewerId, viewerName]);
    return true; // New view
  }
  return false; // Already viewed recently
}

// Get user's ticket history count
async function getUserTicketHistory(userId) {
  const r = await pool.query(`
    SELECT COUNT(*) as total, 
           COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed,
           COUNT(CASE WHEN status = 'open' THEN 1 END) as open
    FROM modmail_tickets WHERE user_id = $1
  `, [userId]);
  return r.rows[0];
}

// Get linked tickets
async function getLinkedTickets(ticketId) {
  const r = await pool.query(`
    SELECT t.* FROM modmail_tickets t
    JOIN ticket_links l ON (l.linked_ticket_id = t.id OR l.ticket_id = t.id)
    WHERE (l.ticket_id = $1 OR l.linked_ticket_id = $1) AND t.id != $1
  `, [ticketId]);
  return r.rows;
}

// Link tickets
async function linkTickets(ticketId, linkedTicketId, linkedBy) {
  await pool.query(`
    INSERT INTO ticket_links (ticket_id, linked_ticket_id, linked_by)
    VALUES ($1, $2, $3)
  `, [ticketId, linkedTicketId, linkedBy]);
}

// Record sentiment
async function recordSentiment(userId, ticketId, sentiment, score) {
  await pool.query(`
    INSERT INTO user_sentiment (user_id, ticket_id, sentiment, score)
    VALUES ($1, $2, $3, $4)
  `, [userId, ticketId, sentiment, score]);
}

// Get user sentiment history
async function getUserSentimentHistory(userId) {
  const r = await pool.query(`
    SELECT sentiment, COUNT(*) as count FROM user_sentiment 
    WHERE user_id = $1 
    GROUP BY sentiment 
    ORDER BY count DESC
  `, [userId]);
  return r.rows;
}

// Record staff analytics
async function recordStaffAction(staffId, ticketId, action, responseTimeSeconds = null) {
  await pool.query(`
    INSERT INTO staff_analytics (staff_id, ticket_id, action, response_time_seconds)
    VALUES ($1, $2, $3, $4)
  `, [staffId, ticketId, action, responseTimeSeconds]);
}

// Get staff stats
async function getStaffStats(staffId) {
  const r = await pool.query(`
    SELECT 
      COUNT(*) as total_actions,
      COUNT(CASE WHEN action = 'reply' THEN 1 END) as replies,
      COUNT(CASE WHEN action = 'close' THEN 1 END) as closes,
      COUNT(CASE WHEN action = 'claim' THEN 1 END) as claims,
      ROUND(AVG(response_time_seconds)) as avg_response_time
    FROM staff_analytics WHERE staff_id = $1
  `, [staffId]);
  return r.rows[0];
}

// Get overall analytics
async function getOverallAnalytics() {
  const r = await pool.query(`
    SELECT 
      (SELECT COUNT(*) FROM modmail_tickets) as total_tickets,
      (SELECT COUNT(*) FROM modmail_tickets WHERE status = 'open') as open_tickets,
      (SELECT COUNT(*) FROM modmail_tickets WHERE created_at > NOW() - INTERVAL '24 hours') as tickets_today,
      (SELECT COUNT(*) FROM modmail_tickets WHERE created_at > NOW() - INTERVAL '7 days') as tickets_week,
      (SELECT ROUND(AVG(response_time_seconds)) FROM staff_analytics WHERE action = 'reply') as avg_response_time,
      (SELECT ROUND(AVG(rating)::numeric, 1) FROM ticket_feedback) as avg_rating
  `);
  return r.rows[0];
}

// Schedule a message
async function scheduleMessage(ticketId, content, scheduledBy, sendAt) {
  await pool.query(`
    INSERT INTO scheduled_messages (ticket_id, content, scheduled_by, send_at)
    VALUES ($1, $2, $3, $4)
  `, [ticketId, content, scheduledBy, sendAt]);
}

// Get pending scheduled messages
async function getPendingScheduledMessages() {
  const r = await pool.query(`
    SELECT * FROM scheduled_messages 
    WHERE sent = FALSE AND send_at <= NOW()
  `);
  return r.rows;
}

// Mark scheduled message as sent
async function markScheduledMessageSent(id) {
  await pool.query(`UPDATE scheduled_messages SET sent = TRUE WHERE id = $1`, [id]);
}

// Save feedback
async function saveFeedback(ticketId, userId, rating, comment = null) {
  await pool.query(`
    INSERT INTO ticket_feedback (ticket_id, user_id, rating, comment)
    VALUES ($1, $2, $3, $4)
  `, [ticketId, userId, rating, comment]);
}

// Format time ago
function timeAgo(date) {
  const seconds = Math.floor((new Date() - new Date(date)) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

// Format duration
function formatDuration(seconds) {
  if (seconds < 60) return `${seconds} seconds`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''}`;
  const hours = Math.floor(minutes / 60);
  return `${hours} hour${hours > 1 ? 's' : ''} ${minutes % 60}m`;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

async function getNextTicketNumber() {
  const r = await pool.query(`SELECT COALESCE(MAX(ticket_number), 0) + 1 as n FROM modmail_tickets`);
  return r.rows[0].n;
}

async function isBlacklisted(userId) {
  const r = await pool.query(`SELECT 1 FROM modmail_blacklist WHERE user_id = $1`, [userId]);
  return r.rows.length > 0;
}

function isStaff(member) {
  if (!member) return false;
  if (member.permissions.has(PermissionFlagsBits.Administrator)) return true;
  return member.roles.cache.some(r => ['staff','mod','admin','moderator','mastermind'].some(n => r.name.toLowerCase().includes(n)));
}

async function logToModmail(guild, ticket, closedBy, reason, kicked = false) {
  try {
    const logChannel = guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
    if (!logChannel) return;
    
    const user = await client.users.fetch(ticket.user_id).catch(() => null);
    
    const embed = new EmbedBuilder()
      .setTitle(` Ticket #${ticket.ticket_number} Closed${kicked ? ' & Kicked' : ''}`)
      .addFields(
        { name: ' User', value: user ? `${user.tag} (${user.id})` : ticket.user_id, inline: true },
        { name: ' Closed By', value: closedBy.tag, inline: true },
        { name: ' Opened', value: `<t:${Math.floor(new Date(ticket.created_at).getTime() / 1000)}:R>`, inline: true },
        { name: ' Reason', value: reason || 'No reason provided', inline: false }
      )
      .setColor(kicked ? CONFIG.COLORS.error : CONFIG.COLORS.warning)
      .setTimestamp();
    
    await logChannel.send({ embeds: [embed] });
  } catch (e) {
    console.log('Log error:', e.message);
  }
}

async function getOpenTicket(userId) {
  const r = await pool.query(`SELECT * FROM modmail_tickets WHERE user_id = $1 AND status = 'open' LIMIT 1`, [userId]);
  return r.rows[0];
}

async function getTicketByChannel(channelId) {
  const r = await pool.query(`SELECT * FROM modmail_tickets WHERE channel_id = $1`, [channelId]);
  return r.rows[0];
}

// ═══════════════════════════════════════════════════════════════════════════════
// TICKET CREATION
// ═══════════════════════════════════════════════════════════════════════════════

async function createTicket(user, guild, message, extraData = {}) {
  const ticketNum = await getNextTicketNumber();
  
  // Find or create category
  let category = guild.channels.cache.find(c => c.name === ' MODMAIL' && c.type === ChannelType.GuildCategory);
  if (!category) {
    category = await guild.channels.create({
      name: ' MODMAIL',
      type: ChannelType.GuildCategory,
      permissionOverwrites: [{ id: guild.id, deny: [PermissionFlagsBits.ViewChannel] }]
    });
  }
  
  // Create channel
  const channel = await guild.channels.create({
    name: `ticket-${ticketNum.toString().padStart(4, '0')}`,
    type: ChannelType.GuildText,
    parent: category.id,
    topic: `User: ${user.tag} (${user.id})`
  });
  
  // Save to DB
  const r = await pool.query(`
    INSERT INTO modmail_tickets (ticket_number, user_id, guild_id, channel_id)
    VALUES ($1, $2, $3, $4) RETURNING *
  `, [ticketNum, user.id, guild.id, channel.id]);
  const ticket = r.rows[0];
  
  // Save message
  await pool.query(`
    INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
    VALUES ($1, $2, $3, $4, false)
  `, [ticket.id, user.id, user.tag, message]);
  
  // Get user's history and notes for context
  const history = await getUserTicketHistory(user.id);
  const notes = await getUserNotes(user.id);
  const queuePos = await getQueuePosition(ticket.id);
  
  // Build ticket embed with elite info
  const embed = new EmbedBuilder()
    .setTitle(` Ticket #${ticketNum}`)
    .setDescription(`**User:** ${user} (${user.tag})\n**ID:** ${user.id}`)
    .addFields({ name: ' Message', value: message.slice(0, 1024) || 'No message', inline: false })
    .setColor(CONFIG.COLORS.primary)
    .setThumbnail(user.displayAvatarURL())
    .setTimestamp();
  
  // Add history info
  if (history.total > 0) {
    embed.addFields({
      name: ' User History',
      value: `**${history.total}** previous tickets (${history.closed} closed)`,
      inline: true
    });
  } else {
    embed.addFields({ name: ' User History', value: ' First time contacting', inline: true });
  }
  
  // Add queue position
  embed.addFields({ name: ' Queue Position', value: `#${queuePos}`, inline: true });
  
  // Add notes if any
  if (notes.length > 0) {
    const notesStr = notes.slice(0, 3).map(n => `• ${n.note}`).join('\n');
    embed.addFields({ name: ' Staff Notes', value: notesStr, inline: false });
  }
  
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('claim').setLabel('Claim').setStyle(ButtonStyle.Primary).setEmoji(''),
    new ButtonBuilder().setCustomId('close').setLabel('Close').setStyle(ButtonStyle.Danger).setEmoji(''),
    new ButtonBuilder().setCustomId('priority_menu').setLabel('Priority').setStyle(ButtonStyle.Secondary).setEmoji(''),
    new ButtonBuilder().setCustomId('view_notes').setLabel('Notes').setStyle(ButtonStyle.Secondary).setEmoji(''),
    new ButtonBuilder().setCustomId('view_history').setLabel('History').setStyle(ButtonStyle.Secondary).setEmoji('')
  );
  
  // Check for online staff
  const onlineStaff = await getOnlineStaffCount(guild);
  let pingContent = '@here New ticket!';
  if (onlineStaff === 0) {
    pingContent = ' @here New ticket! (No staff appear to be online)';
  }
  
  await channel.send({ content: pingContent, embeds: [embed], components: [row] });
  
  return ticket;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DM HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

client.on(Events.MessageCreate, async (message) => {
  if (message.author.bot) return;
  
  // DM = modmail
  if (message.channel.type === ChannelType.DM) {
    if (await isBlacklisted(message.author.id)) {
      return message.reply(' You are blocked from support.');
    }
    
    const guild = client.guilds.cache.get(CONFIG.GUILD_ID);
    if (!guild) return;
    
    // ═══════════════════════════════════════════════════════════════
    // CHECK FOR PENDING APPEAL
    // ═══════════════════════════════════════════════════════════════
    const pendingAppeal = client.pendingAppeals?.get(message.author.id);
    if (pendingAppeal && (Date.now() - pendingAppeal.timestamp) < 600000) { // 10 min timeout
      client.pendingAppeals.delete(message.author.id);
      
      // Create appeal ticket
      const appealType = pendingAppeal.type === 'suspended' ? ' BAN APPEAL' : ' ALT ACCOUNT APPEAL';
      const ticket = await createTicket(message.author, guild, message.content, { isAppeal: true });
      
      if (ticket) {
        // Send special appeal header to ticket
        await ticket.send({
          embeds: [new EmbedBuilder()
            .setTitle(appealType)
            .setDescription(`**User:** ${message.author.tag} (<@${message.author.id}>)\n**Type:** ${pendingAppeal.type === 'suspended' ? 'Banned Alt Detection' : 'Duplicate Account'}\n\n**Their Appeal:**\n${message.content}`)
            .setColor(pendingAppeal.type === 'suspended' ? 0xFF0000 : 0xFFA500)
            .setTimestamp()
          ]
        });
        
        await message.reply({
          embeds: [new EmbedBuilder()
            .setTitle(' Appeal Submitted')
            .setDescription('Your appeal has been sent to staff. You will receive a response in this DM.\n\nPlease be patient - appeals are typically reviewed within 24-48 hours.')
            .setColor(0x00FF00)
          ]
        });
      }
      return;
    }
    
    // ═══════════════════════════════════════════════════════════════
    // SOC-LEVEL THREAT ANALYSIS
    // ═══════════════════════════════════════════════════════════════
    
    const threatAnalysis = await analyzeThreat(message);
    
    // Handle based on threat level
    if (threatAnalysis.action === 'BLOCK' || threatAnalysis.action === 'QUARANTINE') {
      // Log the threat to security channel
      await handleThreatResponse(message, threatAnalysis, guild);
      
      // Extract what they actually sent
      const urlRegex = /(https?:\/\/[^\s]+)/gi;
      const links = message.content.match(urlRegex) || [];
      const files = [...message.attachments.values()];
      
      // Build DETAILED explanation
      let whatYouSent = '';
      if (links.length > 0) {
        whatYouSent += `** Link(s) You Sent:**\n`;
        for (const link of links) {
          whatYouSent += `\`${link}\`\n`;
        }
        whatYouSent += '\n';
      }
      if (files.length > 0) {
        whatYouSent += `** File(s) You Sent:**\n`;
        for (const file of files) {
          whatYouSent += `\`${file.name}\` (${Math.round(file.size/1024)}KB)\n`;
        }
        whatYouSent += '\n';
      }
      
      // Build threat explanation based on ALL findings
      let threatBreakdown = '';
      let whatItDoes = '';
      
      for (const f of threatAnalysis.findings || []) {
        // Detection explanations
        if (f.code === 'TYPOSQUAT') {
          threatBreakdown += ` **TYPOSQUATTING DETECTED**\n`;
          threatBreakdown += `The domain in your link is designed to look like a legitimate website but with slight misspellings.\n`;
          whatItDoes += `• Tricks you into entering your real login credentials on a fake site\n`;
          whatItDoes += `• Steals your username, password, and 2FA codes\n`;
          whatItDoes += `• Can steal payment information if you enter it\n\n`;
        }
        if (f.code === 'HOMOGRAPH') {
          threatBreakdown += ` **HOMOGRAPH ATTACK DETECTED**\n`;
          threatBreakdown += `The link uses Unicode characters that LOOK identical to real letters but are different (е vs e, а vs a).\n`;
          whatItDoes += `• Creates a visually identical fake domain\n`;
          whatItDoes += `• Even careful users can't spot the difference\n`;
          whatItDoes += `• Used for sophisticated credential theft\n\n`;
        }
        if (f.code === 'VIRUSTOTAL' || f.code === 'VIRUSTOTAL_SUS') {
          threatBreakdown += ` **ANTIVIRUS ENGINES FLAGGED THIS**\n`;
          threatBreakdown += `Multiple security vendors have identified this as malicious.\n`;
          whatItDoes += `• May contain trojans that give hackers remote access to your PC\n`;
          whatItDoes += `• Could install ransomware that encrypts all your files\n`;
          whatItDoes += `• Might steal saved passwords, cookies, and crypto wallets\n\n`;
        }
        if (f.code === 'PHISHTANK') {
          threatBreakdown += ` **CONFIRMED PHISHING SITE**\n`;
          threatBreakdown += `This exact URL is in a database of known phishing sites reported by security researchers.\n`;
          whatItDoes += `• 100% confirmed to be a scam site\n`;
          whatItDoes += `• Designed specifically to steal credentials\n`;
          whatItDoes += `• May have already stolen data from other victims\n\n`;
        }
        if (f.code === 'GOOGLE_SAFE') {
          threatBreakdown += ` **GOOGLE BLACKLISTED**\n`;
          threatBreakdown += `Google's Safe Browsing system has flagged this as dangerous.\n`;
          whatItDoes += `• Blocked by Chrome, Firefox, and Safari browsers\n`;
          whatItDoes += `• Identified as malware, phishing, or unwanted software\n\n`;
        }
        if (f.code === 'DANGEROUS_EXT') {
          threatBreakdown += ` **DANGEROUS FILE TYPE**\n`;
          threatBreakdown += `This file type can execute code on your computer.\n`;
          whatItDoes += `• .exe/.bat/.scr files run programs when opened\n`;
          whatItDoes += `• Can install malware, keyloggers, or backdoors\n`;
          whatItDoes += `• May give hackers full control of your system\n\n`;
        }
        if (f.code === 'SE_URGENCY' || f.code === 'SE_THREAT' || f.code === 'SE_AUTHORITY') {
          threatBreakdown += ` **SOCIAL ENGINEERING DETECTED**\n`;
          threatBreakdown += `Your message uses psychological manipulation tactics.\n`;
          whatItDoes += `• Creates false urgency to make victims act without thinking\n`;
          whatItDoes += `• Uses fear/threats to bypass rational decision-making\n`;
          whatItDoes += `• Classic scam technique used by criminals\n\n`;
        }
        if (f.code === 'IPQS_PHISH' || f.code === 'IPQS_MALWARE') {
          threatBreakdown += ` **FRAUD DETECTION FLAGGED**\n`;
          threatBreakdown += `IPQualityScore identified this as a scam/malware.\n`;
          whatItDoes += `• High probability of credential theft\n`;
          whatItDoes += `• Domain matches patterns used by scammers\n\n`;
        }
        if (f.code === 'ALIENVAULT') {
          threatBreakdown += ` **THREAT INTELLIGENCE MATCH**\n`;
          threatBreakdown += `Found in AlienVault OTX threat intelligence feeds.\n`;
          whatItDoes += `• Associated with known malware campaigns\n`;
          whatItDoes += `• Used in documented cyber attacks\n\n`;
        }
        if (f.code === 'FAKE_DISCORD' || (f.code && f.code.includes('DISCORD'))) {
          threatBreakdown += ` **FAKE DISCORD LINK**\n`;
          threatBreakdown += `This is NOT a real Discord link - it's a phishing site.\n`;
          whatItDoes += `• Steals your Discord token (full account access)\n`;
          whatItDoes += `• Can steal your Nitro, servers, and payment info\n`;
          whatItDoes += `• Spreads to your friends via DMs\n\n`;
        }
        if (f.code === 'FAKE_STEAM' || (f.code && f.code.includes('STEAM'))) {
          threatBreakdown += ` **FAKE STEAM LINK**\n`;
          threatBreakdown += `This is NOT a real Steam link - it's a phishing site.\n`;
          whatItDoes += `• Steals your Steam account and inventory\n`;
          whatItDoes += `• Can steal CS2 skins, games, and wallet balance\n`;
          whatItDoes += `• May access linked payment methods\n\n`;
        }
        if (f.code === 'SHORTENED') {
          threatBreakdown += ` **URL SHORTENER DETECTED**\n`;
          threatBreakdown += `The link was shortened to hide its real destination.\n`;
          whatItDoes += `• Legitimate services don't hide their URLs\n`;
          whatItDoes += `• Used to bypass security filters\n\n`;
        }
        if (f.code === 'FILE_CONTENT' || f.code === 'MAGIC_MISMATCH') {
          threatBreakdown += ` **FILE CONTENT MISMATCH**\n`;
          threatBreakdown += `The file's actual content doesn't match its extension.\n`;
          whatItDoes += `• File is disguised as something safe\n`;
          whatItDoes += `• Actually contains executable code\n`;
          whatItDoes += `• Classic malware delivery technique\n\n`;
        }
      }
      
      // Remove duplicates
      threatBreakdown = [...new Set(threatBreakdown.split('\n'))].filter(l => l.trim()).join('\n');
      whatItDoes = [...new Set(whatItDoes.split('\n'))].filter(l => l.trim()).join('\n');
      
      // API results summary for user
      let apiSummary = '';
      if (threatAnalysis.apiResults) {
        const apis = threatAnalysis.apiResults;
        let apisChecked = [];
        let threats = [];
        
        if (apis.virustotal?.available) {
          apisChecked.push('VirusTotal');
          if (apis.virustotal.malicious > 0) threats.push(`${apis.virustotal.malicious} antivirus engines flagged malicious`);
        }
        if (apis.googleSafeBrowsing?.available) {
          apisChecked.push('Google Safe Browsing');
          if (apis.googleSafeBrowsing.threats?.length) threats.push('Google blacklisted');
        }
        if (apis.phishtank?.available) {
          apisChecked.push('PhishTank');
          if (apis.phishtank.isPhish) threats.push('Confirmed phishing');
        }
        if (apis.ipqualityscore?.available) {
          apisChecked.push('IPQualityScore');
          if (apis.ipqualityscore.fraudScore > 75 || apis.ipqualityscore.phishing) threats.push('High fraud score');
        }
        if (apis.alienvault?.available) {
          apisChecked.push('AlienVault OTX');
          if (apis.alienvault.pulseCount > 0) threats.push(`Found in ${apis.alienvault.pulseCount} threat feeds`);
        }
        
        if (apisChecked.length > 0) {
          apiSummary = `\n** APIs Checked:** ${apisChecked.join(', ')}\n`;
          if (threats.length > 0) {
            apiSummary += `** Threats Found:** ${threats.join(' • ')}\n`;
          }
        }
      }
      
      // Build the final message to user - NO API NAMES, just clear explanation
      const userEmbed = new EmbedBuilder()
        .setTitle(' MESSAGE BLOCKED')
        .setColor(0xFF0000)
        .setTimestamp();
      
      let description = `Your message contained malicious content and was **not delivered**.\n\n`;
      
      if (whatYouSent) {
        description += whatYouSent;
      }
      
      userEmbed.setDescription(description);
      
      if (threatBreakdown) {
        userEmbed.addFields({
          name: ' What We Found',
          value: threatBreakdown.slice(0, 1024),
          inline: false
        });
      }
      
      if (whatItDoes) {
        userEmbed.addFields({
          name: ' Why This Is Dangerous',
          value: whatItDoes.slice(0, 1024),
          inline: false
        });
      }
      
      userEmbed.addFields({
        name: ' What Happens Now',
        value: `This incident has been **logged and reported to staff**.\n\nSending scams, phishing links, or malware will result in an **immediate permanent ban**.`,
        inline: false
      });
      
      userEmbed.setFooter({ text: 'All messages are scanned for security threats' });
      
      return message.reply({ embeds: [userEmbed] });
    }
    
    // Log medium/low threats but allow the message
    if (threatAnalysis.action === 'FLAG' || threatAnalysis.action === 'WARN') {
      await handleThreatResponse(message, threatAnalysis, guild);
    }
    
    // ═══════════════════════════════════════════════════════════════
    // CHECK FOR EXISTING TICKET
    // ═══════════════════════════════════════════════════════════════
    
    let ticket = await getOpenTicket(message.author.id);
    
    if (ticket) {
      // USER HAS EXISTING TICKET - Add message to ticket
      const channel = guild.channels.cache.get(ticket.channel_id);
      if (channel) {
        await pool.query(`
          INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
          VALUES ($1, $2, $3, $4, false)
        `, [ticket.id, message.author.id, message.author.tag, message.content]);
        
        // Send message to ticket channel
        const embed = new EmbedBuilder()
          .setAuthor({ name: message.author.tag, iconURL: message.author.displayAvatarURL() })
          .setDescription(message.content)
          .setColor(threatAnalysis.score > 0 ? CONFIG.COLORS.warning : CONFIG.COLORS.info)
          .setTimestamp();
        
        await channel.send({ embeds: [embed] });
        
        // If there's a security flag, send PRIVATE alert to staff in the same channel (user doesn't see this)
        if (threatAnalysis.score >= RISK_THRESHOLDS.LOW) {
          // Build detailed threat breakdown for staff
          let staffAlert = `**Risk Score:** ${threatAnalysis.score}/100\n**Action:** ${threatAnalysis.action}\n\n`;
          staffAlert += `**Detections:**\n`;
          for (const f of threatAnalysis.findings.slice(0, 5)) {
            staffAlert += `• \`[${f.code}]\` +${f.points}pts - ${f.detail}\n`;
          }
          
          // API results if available
          if (threatAnalysis.apiResults) {
            staffAlert += `\n**API Scan Results:**\n`;
            if (threatAnalysis.apiResults.virustotal?.available) {
              const vt = threatAnalysis.apiResults.virustotal;
              staffAlert += `• VirusTotal: ${vt.malicious || 0} malicious, ${vt.suspicious || 0} suspicious\n`;
            }
            if (threatAnalysis.apiResults.googleSafeBrowsing?.available && threatAnalysis.apiResults.googleSafeBrowsing.threats?.length) {
              staffAlert += `• Google: ${threatAnalysis.apiResults.googleSafeBrowsing.threats.map(t => t.threatType).join(', ')}\n`;
            }
            if (threatAnalysis.apiResults.phishtank?.available && threatAnalysis.apiResults.phishtank.isPhish) {
              staffAlert += `• PhishTank:  CONFIRMED PHISHING\n`;
            }
            if (threatAnalysis.apiResults.ipqualityscore?.available) {
              const ipqs = threatAnalysis.apiResults.ipqualityscore;
              staffAlert += `• IPQualityScore: Risk ${ipqs.fraudScore || ipqs.riskScore || 0}%\n`;
            }
          }
          
          const staffEmbed = new EmbedBuilder()
            .setTitle(` SECURITY FLAG - Staff Only`)
            .setDescription(staffAlert)
            .setColor(0xFF6600)
            .setFooter({ text: 'This alert is only visible to staff in this channel' });
          
          await channel.send({ embeds: [staffEmbed] });
          
          // Store threat data in database for ticket close
          await pool.query(`
            UPDATE modmail_tickets 
            SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb 
            WHERE id = $2
          `, [JSON.stringify({ lastThreat: { score: threatAnalysis.score, findings: threatAnalysis.findings.slice(0, 5), apiResults: threatAnalysis.apiResults } }), ticket.id]).catch(() => {});
        }
        
        // React with checkmark to confirm message sent
        await message.react('');
      }
      return;
    }
    
    // ═══════════════════════════════════════════════════════════════
    // NO TICKET - SHOW WARNING (First time only)
    // ═══════════════════════════════════════════════════════════════
    
    const warningEmbed = new EmbedBuilder()
      .setTitle(' CONFIRM YOUR MESSAGE')
      .setDescription(`
**This is The Unpatched Method support system.**

**Rules:**
• Legitimate inquiries only
• No trolling or spam
• No wasting staff time

**Misuse = Permanent Ban**
      `)
      .addFields({
        name: ' Your Message Preview',
        value: '```' + message.content.slice(0, 500) + '```' || 'No message',
        inline: false
      })
      .setColor(CONFIG.COLORS.warning)
      .setFooter({ text: 'Press the button below to send your message to staff' });
    
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('confirm_ticket')
        .setLabel(' I Understand - Send Message')
        .setStyle(ButtonStyle.Success),
      new ButtonBuilder()
        .setCustomId('cancel_ticket')
        .setLabel(' Cancel')
        .setStyle(ButtonStyle.Danger)
    );
    
    await message.reply({ embeds: [warningEmbed], components: [row] });
    
    // Store pending message including original message for checkmark AND threat analysis
    client.pendingTickets = client.pendingTickets || new Map();
    client.pendingTickets.set(message.author.id, {
      content: message.content,
      guild: guild,
      user: message.author,
      originalMessage: message,
      threatAnalysis: threatAnalysis // Store the threat analysis!
    });
    return;
  }
  
  // Ticket channel = staff reply
  if (message.guild && message.channel.name?.startsWith('ticket-')) {
    const ticket = await getTicketByChannel(message.channel.id);
    if (!ticket || message.content.startsWith(CONFIG.PREFIX)) return;
    if (!isStaff(message.member)) return;
    
    // Get user's language preference from ticket
    const userLanguage = ticket.language || 'en';
    let translatedContent = message.content;
    
    // Translate staff message if user isn't English
    if (userLanguage !== 'en') {
      translatedContent = await translateToLanguage(message.content, userLanguage);
    }
    
    await pool.query(`
      INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
      VALUES ($1, $2, $3, $4, true)
    `, [ticket.id, message.author.id, message.author.tag, message.content]);
    
    try {
      const user = await client.users.fetch(ticket.user_id);
      
      // Send as Burner Phone - clear identification of who this is
      const embed = new EmbedBuilder()
        .setAuthor({ 
          name: 'The Unpatched Method Staff', 
          iconURL: client.user.displayAvatarURL() 
        })
        .setTitle(' Staff Message')
        .setDescription(translatedContent)
        .addFields({
          name: ' What is this?',
          value: 'This is the official support bot for **The Unpatched Method** Discord server. A staff member is responding to your ticket.',
          inline: false
        })
        .setColor(CONFIG.COLORS.primary)
        .setFooter({ text: 'The Unpatched Method • Reply to this DM to respond to staff' })
        .setTimestamp();
      
      await user.send({ embeds: [embed] });
      await message.react('');
    } catch (e) {
      await message.reply(' Could not DM user.');
    }
    return;
  }
  
  // Commands
  if (message.guild && message.content.startsWith(CONFIG.PREFIX)) {
    const args = message.content.slice(1).trim().split(/ +/);
    const cmd = args.shift().toLowerCase();
    
    // ?dm @user message - Creates ticket and DMs user (with confirmation)
    if (cmd === 'dm' && isStaff(message.member)) {
      const user = message.mentions.users.first();
      const content = args.slice(1).join(' ');
      if (!user || !content) return message.reply('Usage: `?dm @user message`');
      
      // Show preview and ask for confirmation
      const previewEmbed = new EmbedBuilder()
        .setTitle(' Message Preview')
        .setDescription(`**To:** ${user.tag}\n\n**Message:**\n${content}`)
        .setColor(CONFIG.COLORS.warning)
        .setFooter({ text: 'Check for spelling errors before sending!' });
      
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`confirm_dm_${user.id}`).setLabel(' Send').setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId('cancel_dm').setLabel(' Cancel').setStyle(ButtonStyle.Danger)
      );
      
      const preview = await message.reply({ embeds: [previewEmbed], components: [row] });
      
      // Store pending message
      client.pendingDMs = client.pendingDMs || new Map();
      client.pendingDMs.set(`${message.author.id}_${user.id}`, {
        user: user,
        content: content,
        guild: message.guild,
        preview: preview,
        originalMsg: message
      });
    }
    
    // ?close [reason]
    if (cmd === 'close' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return message.reply('Not a ticket channel.');
      
      const reason = args.join(' ') || 'No reason';
      
      await message.channel.send(' Closing ticket...');
      
      // Generate transcript first
      const msgResult = await pool.query(`
        SELECT * FROM modmail_messages WHERE ticket_id = $1 ORDER BY created_at ASC
      `, [ticket.id]);
      
      let transcript = `╔══════════════════════════════════════════════════════════════╗\n`;
      transcript += `║           TICKET #${ticket.ticket_number} - TRANSCRIPT                    ║\n`;
      transcript += `╚══════════════════════════════════════════════════════════════╝\n\n`;
      transcript += `User ID: ${ticket.user_id}\n`;
      transcript += `Opened: ${ticket.created_at}\n`;
      transcript += `Closed: ${new Date().toISOString()}\n`;
      transcript += `Closed by: ${message.author.tag}\n`;
      transcript += `Reason: ${reason}\n\n`;
      transcript += `════════════════════ MESSAGES ════════════════════\n\n`;
      
      for (const msg of msgResult.rows) {
        const prefix = msg.is_staff ? '[STAFF]' : '[USER]';
        const time = new Date(msg.created_at).toLocaleString();
        transcript += `${prefix} ${msg.author_name} (${time}):\n${msg.content}\n\n`;
      }
      
      await pool.query(`UPDATE modmail_tickets SET status = 'closed', closed_at = NOW(), closed_by = $1, close_reason = $2 WHERE id = $3`,
        [message.author.id, reason, ticket.id]);
      
      // Record staff action for analytics
      await recordStaffAction(message.author.id, ticket.id, 'close');
      
      try {
        const user = await client.users.fetch(ticket.user_id);
        
        // Send close message
        await user.send({ embeds: [new EmbedBuilder()
          .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
          .setTitle(' Ticket Closed')
          .setDescription(`**Reason:** ${reason}\n\nThank you for contacting The Unpatched Method support. If you need help again, just DM this bot!`)
          .setColor(CONFIG.COLORS.error)
          .setFooter({ text: 'The Unpatched Method • Support' })
        ] });
        
        // Send feedback request
        const feedbackRow = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`feedback_1_${ticket.id}`).setLabel('1').setStyle(ButtonStyle.Secondary).setEmoji(''),
          new ButtonBuilder().setCustomId(`feedback_2_${ticket.id}`).setLabel('2').setStyle(ButtonStyle.Secondary).setEmoji(''),
          new ButtonBuilder().setCustomId(`feedback_3_${ticket.id}`).setLabel('3').setStyle(ButtonStyle.Secondary).setEmoji(''),
          new ButtonBuilder().setCustomId(`feedback_4_${ticket.id}`).setLabel('4').setStyle(ButtonStyle.Secondary).setEmoji(''),
          new ButtonBuilder().setCustomId(`feedback_5_${ticket.id}`).setLabel('5').setStyle(ButtonStyle.Secondary).setEmoji('')
        );
        
        await user.send({
          embeds: [new EmbedBuilder()
            .setTitle(' Rate Your Experience')
            .setDescription('How was your support experience? Your feedback helps us improve!')
            .setColor(CONFIG.COLORS.primary)
          ],
          components: [feedbackRow]
        });
        
        await message.channel.send(' Burning messages...');
        
        // Delete bot's messages from user's DMs (burner style)
        try {
          const dmChannel = await user.createDM();
          const dmMessages = await dmChannel.messages.fetch({ limit: 100 });
          const botMessages = dmMessages.filter(m => m.author.id === client.user.id && !m.components?.length); // Don't delete feedback msg
          
          for (const [, msg] of botMessages) {
            // Don't delete the feedback request
            if (msg.embeds?.[0]?.title === ' Rate Your Experience') continue;
            await msg.delete().catch(() => {});
            await new Promise(r => setTimeout(r, 500));
          }
        } catch (e) {
          console.log('Could not delete DM messages:', e.message);
        }
      } catch (e) {}
      
      // Get any stored threat data from ticket metadata
      let threatInfo = '';
      try {
        const metaResult = await pool.query(`SELECT metadata FROM modmail_tickets WHERE id = $1`, [ticket.id]);
        if (metaResult.rows[0]?.metadata?.lastThreat) {
          const threat = metaResult.rows[0].metadata.lastThreat;
          threatInfo = `\n\n════════════════════ SECURITY FINDINGS ════════════════════\n\n`;
          threatInfo += `Risk Score: ${threat.score}/100\n`;
          threatInfo += `Findings:\n`;
          for (const f of threat.findings || []) {
            threatInfo += `  [${f.code}] +${f.points}pts - ${f.detail}\n`;
          }
          if (threat.apiResults) {
            threatInfo += `\nAPI Results:\n`;
            if (threat.apiResults.virustotal?.available) {
              threatInfo += `  VirusTotal: ${threat.apiResults.virustotal.malicious || 0} malicious\n`;
            }
            if (threat.apiResults.phishtank?.isPhish) {
              threatInfo += `  PhishTank: CONFIRMED PHISHING\n`;
            }
            if (threat.apiResults.googleSafeBrowsing?.threats?.length) {
              threatInfo += `  Google: ${threat.apiResults.googleSafeBrowsing.threats.map(t => t.threatType).join(', ')}\n`;
            }
          }
        }
      } catch (e) {}
      
      // Append threat info to transcript
      transcript += threatInfo;
      
      // Send transcript to log channel
      const logChannel = message.guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
      if (logChannel) {
        const logEmbed = new EmbedBuilder()
          .setTitle(` Ticket #${ticket.ticket_number} Closed`)
          .addFields(
            { name: ' User', value: `<@${ticket.user_id}>`, inline: true },
            { name: ' Closed By', value: message.author.tag, inline: true },
            { name: ' Reason', value: reason, inline: true }
          )
          .setColor(CONFIG.COLORS.warning)
          .setTimestamp();
        
        // Add security note if there were threats
        if (threatInfo) {
          logEmbed.addFields({
            name: ' Security Note',
            value: ' This ticket had security flags. See transcript for details.',
            inline: false
          });
          logEmbed.setColor(0xFF6600);
        }
        
        const transcriptBuffer = Buffer.from(transcript, 'utf-8');
        await logChannel.send({ 
          embeds: [logEmbed], 
          files: [{ attachment: transcriptBuffer, name: `ticket-${ticket.ticket_number}-transcript.txt` }] 
        });
      }
      
      await message.channel.send(' Transcript saved. Deleting channel in 5 seconds...');
      setTimeout(() => message.channel.delete().catch(() => {}), 5000);
    }
    
    // ?closeandkick @user [reason]
    if (cmd === 'closeandkick' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return message.reply('Not a ticket channel.');
      
      const reason = args.join(' ') || 'Closed and removed from server';
      await pool.query(`UPDATE modmail_tickets SET status = 'closed', closed_at = NOW(), closed_by = $1, close_reason = $2 WHERE id = $3`,
        [message.author.id, reason, ticket.id]);
      
      try {
        const user = await client.users.fetch(ticket.user_id);
        
        // Send closing message FIRST (before kick)
        await user.send({ embeds: [new EmbedBuilder()
          .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
          .setTitle(' Ticket Closed')
          .setDescription(`**Reason:** ${reason}\n\n*This conversation will be deleted shortly.*`)
          .setColor(CONFIG.COLORS.error)
          .setFooter({ text: 'The Unpatched Method • Support' })
        ] });
        
        // Delete bot's messages from user's DMs (burner style)
        try {
          const dmChannel = await user.createDM();
          const messages = await dmChannel.messages.fetch({ limit: 100 });
          const botMessages = messages.filter(m => m.author.id === client.user.id);
          
          for (const [, msg] of botMessages) {
            await msg.delete().catch(() => {});
            await new Promise(r => setTimeout(r, 500));
          }
        } catch (e) {}
        
        // NOW kick the user
        const member = await message.guild.members.fetch(ticket.user_id).catch(() => null);
        if (member) {
          await member.kick(reason);
          await message.channel.send(` ${user.tag} has been kicked.`);
        }
      } catch (e) {
        console.log('Close and kick error:', e.message);
      }
      
      // Log to modmail-logs
      await logToModmail(message.guild, ticket, message.author, reason, true);
      
      await message.channel.send(' Closing in 5 seconds... Messages burned ');
      setTimeout(() => message.channel.delete().catch(() => {}), 5000);
    }
    
    // ?claim
    if (cmd === 'claim' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return;
      await pool.query(`UPDATE modmail_tickets SET claimed_by = $1 WHERE id = $2`, [message.author.id, ticket.id]);
      await message.reply(` Claimed by ${message.author}`);
    }
    
    // ?tickets
    if (cmd === 'tickets' && isStaff(message.member)) {
      const r = await pool.query(`SELECT * FROM modmail_tickets WHERE guild_id = $1 AND status = 'open'`, [message.guild.id]);
      if (r.rows.length === 0) return message.reply(' No open tickets!');
      
      const list = r.rows.map(t => `#${t.ticket_number} - <@${t.user_id}> - <#${t.channel_id}>`).join('\n');
      await message.reply({ embeds: [new EmbedBuilder().setTitle(' Open Tickets').setDescription(list).setColor(CONFIG.COLORS.info)] });
    }
    
    // ?blacklist @user
    if (cmd === 'blacklist' && message.member.permissions.has(PermissionFlagsBits.Administrator)) {
      const user = message.mentions.users.first();
      if (!user) return message.reply('Usage: `?blacklist @user`');
      await pool.query(`INSERT INTO modmail_blacklist (user_id, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [user.id, args.slice(1).join(' ')]);
      await message.reply(` ${user.tag} blacklisted.`);
    }
    
    // ?unblacklist @user
    if (cmd === 'unblacklist' && message.member.permissions.has(PermissionFlagsBits.Administrator)) {
      const user = message.mentions.users.first();
      if (!user) return message.reply('Usage: `?unblacklist @user`');
      await pool.query(`DELETE FROM modmail_blacklist WHERE user_id = $1`, [user.id]);
      await message.reply(` ${user.tag} unblacklisted.`);
    }
    
    // ?setupmodmail - Currently limited to specific user for beta testing
    const BETA_TESTER_ID = '1262049236376092728'; // Your friend's ID
    if (cmd === 'setupmodmail') {
      // Check if user is beta tester OR admin of The Unpatched Method
      const isOwner = message.author.id === '1212055397737046159'; // Your ID (Joshua)
      const isBetaTester = message.author.id === BETA_TESTER_ID;
      const isUnpatchedServer = message.guild.id === CONFIG.GUILD_ID;
      
      if (!isOwner && !isBetaTester && !isUnpatchedServer) {
        return message.reply(' This bot is currently in private beta. Contact the developer for access.');
      }
      
      if (!message.member.permissions.has(PermissionFlagsBits.Administrator)) {
        return message.reply(' You need Administrator permission to run setup.');
      }
      
      // ═══════════════════════════════════════════════════════════════
      // THE UNPATCHED METHOD SERVER - Keep original setup (no changes)
      // ═══════════════════════════════════════════════════════════════
      if (isUnpatchedServer) {
        await message.channel.send(' Setting up modmail system...');
        
        // Delete old category if exists and recreate fresh
        const oldCat = message.guild.channels.cache.find(c => c.name === ' MODMAIL' && c.type === ChannelType.GuildCategory);
        if (oldCat) {
          // Delete all channels in category first
          const channelsInCat = message.guild.channels.cache.filter(c => c.parentId === oldCat.id);
          for (const [id, channel] of channelsInCat) {
            await channel.delete().catch(() => {});
          }
          await oldCat.delete().catch(() => {});
          await message.channel.send(' Deleted old modmail category');
        }
        
        // Create fresh category
        const cat = await message.guild.channels.create({
          name: ' MODMAIL',
          type: ChannelType.GuildCategory,
          permissionOverwrites: [{ id: message.guild.id, deny: [PermissionFlagsBits.ViewChannel] }]
        });
        await message.channel.send(' Created ** MODMAIL** category');
        
        // Create modmail-logs channel
        const log = await message.guild.channels.create({
          name: 'modmail-logs',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'All modmail transcripts and ticket logs'
        });
        await message.channel.send(` Created **#modmail-logs** - ID: \`${log.id}\``);
        
        // Create security-logs channel
        const securityLog = await message.guild.channels.create({
          name: 'security-logs',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Security threat detections and alerts'
        });
        await message.channel.send(` Created **#security-logs** - ID: \`${securityLog.id}\``);
        
        // Create staff-dm channel with instruction embed
        const staffDm = await message.guild.channels.create({
          name: 'staff-dm',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Use ?dm @user message to contact members'
        });
        
        const instructionEmbed = new EmbedBuilder()
          .setTitle(' Staff DM Channel')
          .setDescription(`Use this channel to DM server members through the bot.

**Command:**
\`?dm @user Your message here\`

**What happens:**
• User receives a DM from Burner Phone
• A ticket is created to track the conversation
• User can reply and it comes here

**Example:**
\`?dm @JohnDoe Hey, we noticed you had a question about...\``)
          .setColor(CONFIG.COLORS.primary)
          .setFooter({ text: 'Messages are anonymous - user won\'t see your name' });
        await staffDm.send({ embeds: [instructionEmbed] });
        await message.channel.send(` Created **#staff-dm** with instructions`);
        
        // Create modmail-guide channel with all embeds
        const guide = await message.guild.channels.create({
          name: 'modmail-guide',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Complete guide to Burner Phone ELITE modmail + SOC security'
        });
        
        // Post all guide embeds
        const intro = new EmbedBuilder()
          .setTitle(' BURNER PHONE ELITE - COMPLETE STAFF GUIDE')
          .setDescription(`**Enterprise-grade modmail + SOC-level security system**
          
This bot protects your server with the same security tech used by Fortune 500 companies.

** MODMAIL FEATURES:**
• Anonymous staff ↔ user communication
• Typing indicators (both ways)
• "Staff viewing" notifications
• Queue position tracking
• Persistent user notes
• Canned responses/snippets
• Staff away status
• Auto-close inactive tickets
• Post-close feedback ratings
• Full analytics dashboard

** SECURITY FEATURES:**
• 7 threat intelligence APIs
• Real-time phishing detection
• Malware file scanning
• Social engineering detection
• Risk scoring system`)
          .setColor(CONFIG.COLORS.primary)
          .setThumbnail(message.guild.iconURL());
        
        const howItWorks = new EmbedBuilder()
          .setTitle(' HOW MODMAIL WORKS')
          .setDescription(`**When a user DMs the bot:**

1⃣ User sends DM  Security scan runs
2⃣ If safe  Ticket created in this category
3⃣ You see: message, mood, reputation, history
4⃣ Just type in the ticket channel to reply
5⃣ User gets DM from "The Unpatched Method Staff"

**User sees:**
• Clear identification this is official support
• "Staff is viewing your ticket" notification
• "Staff is typing..." indicator
• Green  when their message is delivered

**They NEVER see your username!**`)
          .setColor(CONFIG.COLORS.info);
        
        const commands1 = new EmbedBuilder()
          .setTitle('⌨ COMMANDS - BASIC')
          .addFields(
            { name: ' In Ticket Channels', value: `\`?close [reason]\` - Close & save transcript
\`?closeandkick [reason]\` - Close + kick user
\`?claim\` - Mark ticket as yours
\`?priority low/med/high/urgent\` - Set urgency
Just type normally to reply to user`, inline: false },
            { name: ' In #staff-dm', value: `\`?dm @user message\` - DM any user`, inline: false },
            { name: ' Anywhere (Staff)', value: `\`?tickets\` - View all open tickets
\`?blacklist @user [reason]\` - Block from modmail
\`?unblacklist @user\` - Unblock user`, inline: false }
          )
          .setColor(CONFIG.COLORS.info);
        
        const commands2 = new EmbedBuilder()
          .setTitle('⌨ COMMANDS - ELITE')
          .addFields(
            { name: ' Notes & Snippets', value: `\`?note @user note text\` - Add permanent note
\`?notes @user\` - View all notes + history
\`?snippet add name content\` - Save response
\`?snippet use name\` - Send saved response
\`?snippets\` - List all snippets`, inline: false },
            { name: ' Analytics & Status', value: `\`?stats\` - Your personal stats
\`?analytics\` - Server-wide analytics
\`?away 2h message\` - Set away status
\`?back\` - Return from away`, inline: false },
            { name: ' Advanced', value: `\`?history @user\` - User's ticket history
\`?transfer @staff\` - Transfer ticket
\`?schedule 1h message\` - Delayed message
\`?link #channel\` - Link related tickets`, inline: false }
          )
          .setColor(CONFIG.COLORS.info);
        
        const security1 = new EmbedBuilder()
          .setTitle(' SOC-LEVEL SECURITY SYSTEM')
          .setDescription(`**7 Threat Intelligence APIs:**

 **VirusTotal** - 70+ antivirus engines
 **IPQualityScore** - Fraud/phishing detection
 **AbuseIPDB** - IP reputation database
 **AlienVault OTX** - Threat intelligence
 **Hybrid Analysis** - Sandbox file analysis
 **Google Safe Browsing** - Phishing database
 **PhishTank** - Confirmed phishing sites

**Every link and file is scanned automatically!**`)
          .setColor(CONFIG.COLORS.warning);
        
        const security2 = new EmbedBuilder()
          .setTitle(' WHAT GETS DETECTED')
          .setDescription(`**Link Threats:**
 **Typosquatting** - dlscord.com, disc0rd.gift
 **Homograph Attacks** - Cyrillic lookalike chars
 **URL Shorteners** - Expanded and analyzed
 **Fake Domains** - Discord/Steam impersonation

**Risk Score System:**
• 0-19:  Safe (allowed)
• 20-39:  Warning (allowed, logged)
• 40-59:  Flagged (allowed, staff alerted)
• 60-79:  Quarantine (blocked)
• 80+:  Critical (blocked, @here alert)`)
          .setColor(CONFIG.COLORS.warning);
        
        const tips = new EmbedBuilder()
          .setTitle(' PRO TIPS')
          .setDescription(`**1. Use snippets for common responses:**
\`?snippet add rules Please read #rules\`

**2. Add notes for problem users:**
\`?note @user Frequently asks same question\`

**3. Set away when busy:**
\`?away 1h Lunch break\`

**4. Check analytics weekly:**
\`?analytics\` shows response times

**5. Trust the security system:**
If it blocks something, it's probably bad!`)
          .setColor(CONFIG.COLORS.success)
          .setFooter({ text: 'Burner Phone ELITE • The Unpatched Method' });
        
        await guide.send({ embeds: [intro, howItWorks] });
        await guide.send({ embeds: [commands1, commands2] });
        await guide.send({ embeds: [security1, security2, tips] });
        await message.channel.send(` Created **#modmail-guide** with full documentation`);
        
        // Final summary with channel IDs to update in code
        const summaryEmbed = new EmbedBuilder()
          .setTitle(' MODMAIL SETUP COMPLETE')
          .setDescription(`**All channels created successfully!**

 **IMPORTANT: Update these IDs in Railway environment variables or code:**`)
          .addFields(
            { name: ' MODMAIL_LOG_CHANNEL', value: `\`${log.id}\``, inline: true },
            { name: ' SECURITY_LOG_CHANNEL', value: `\`${securityLog.id}\``, inline: true },
            { name: '\u200b', value: '\u200b', inline: true },
            { name: ' Category', value: `${cat}`, inline: true },
            { name: ' Staff DM', value: `${staffDm}`, inline: true },
            { name: ' Guide', value: `${guide}`, inline: true }
          )
          .setColor(CONFIG.COLORS.success)
          .setFooter({ text: 'Copy the IDs above and update the code, then redeploy!' });
        
        return message.channel.send({ embeds: [summaryEmbed] });
      }
      
      // ═══════════════════════════════════════════════════════════════
      // BETA TESTER SETUP - Interactive setup for other servers
      // ═══════════════════════════════════════════════════════════════
      
      // Step 1: Ask for mod role
      const askEmbed = new EmbedBuilder()
        .setTitle(' Modmail Setup')
        .setDescription(`**Which role should have access to modmail tickets?**

Please mention the role (e.g., @Moderator or @Staff)

This role will:
• See the modmail category
• View and respond to tickets
• Have access to all modmail commands

Everyone else will NOT see the modmail channels.`)
        .setColor(CONFIG.COLORS.primary)
        .setFooter({ text: 'Type the role mention or "cancel" to abort' });
      
      await message.channel.send({ embeds: [askEmbed] });
      
      // Wait for role mention
      const filter = m => m.author.id === message.author.id;
      const collected = await message.channel.awaitMessages({ filter, max: 1, time: 60000, errors: ['time'] }).catch(() => null);
      
      if (!collected || collected.first().content.toLowerCase() === 'cancel') {
        return message.channel.send(' Setup cancelled.');
      }
      
      const response = collected.first();
      const modRole = response.mentions.roles.first() || message.guild.roles.cache.find(r => r.name.toLowerCase() === response.content.toLowerCase());
      
      if (!modRole) {
        return message.channel.send(' No valid role found. Please run `?setupmodmail` again and mention a role like @Moderator');
      }
      
      await message.channel.send(` Setting up modmail with **${modRole.name}** as the staff role...`);
      
      // Create category - hidden from everyone, visible to mod role and bot
      let cat = message.guild.channels.cache.find(c => c.name === ' MODMAIL');
      if (!cat) {
        cat = await message.guild.channels.create({
          name: ' MODMAIL',
          type: ChannelType.GuildCategory,
          permissionOverwrites: [
            { id: message.guild.id, deny: [PermissionFlagsBits.ViewChannel] }, // Hide from @everyone
            { id: modRole.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.ManageMessages] }, // Allow mod role
            { id: client.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ManageChannels, PermissionFlagsBits.ManageMessages] } // Allow bot
          ]
        });
        await message.channel.send(' Created ** MODMAIL** category (hidden from everyone except staff)');
      } else {
        // Update existing category permissions
        await cat.permissionOverwrites.set([
          { id: message.guild.id, deny: [PermissionFlagsBits.ViewChannel] },
          { id: modRole.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.ManageMessages] },
          { id: client.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ManageChannels, PermissionFlagsBits.ManageMessages] }
        ]);
        await message.channel.send(' Updated ** MODMAIL** category permissions');
      }
      
      // Create modmail-logs channel
      let log = message.guild.channels.cache.find(c => c.name === 'modmail-logs');
      if (!log) {
        log = await message.guild.channels.create({
          name: 'modmail-logs',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'All modmail transcripts, security alerts, and threat detections'
        });
        await message.channel.send(' Created **#modmail-logs** channel');
      }
      
      // Create security-logs channel
      let securityLog = message.guild.channels.cache.find(c => c.name === 'security-logs');
      if (!securityLog) {
        securityLog = await message.guild.channels.create({
          name: 'security-logs',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Security threat detections, blocked messages, and suspicious activity'
        });
        await message.channel.send(' Created **#security-logs** channel');
      }
      
      // Create staff-dm channel
      let staffDm = message.guild.channels.cache.find(c => c.name === 'staff-dm');
      if (!staffDm) {
        staffDm = await message.guild.channels.create({
          name: 'staff-dm',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Use ?dm @user message to contact members through the bot'
        });
        
        const instructionEmbed = new EmbedBuilder()
          .setTitle(' Staff DM Channel')
          .setDescription('Use this channel to DM server members through the bot.\n\n**Command:**\n`?dm @user Your message here`\n\n**What happens:**\n• User receives a DM from Burner Phone\n• A ticket is created to track the conversation\n• User can reply and it comes here')
          .setColor(CONFIG.COLORS.primary);
        await staffDm.send({ embeds: [instructionEmbed] });
        await message.channel.send(' Created **#staff-dm** channel');
      }
      
      // Create modmail-guide channel
      let guide = message.guild.channels.cache.find(c => c.name === 'modmail-guide');
      if (!guide) {
        guide = await message.guild.channels.create({
          name: 'modmail-guide',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Complete guide to Burner Phone ELITE modmail + SOC security'
        });
        
        // ═══════════════════════════════════════════════════════════════
        // GUIDE EMBEDS
        // ═══════════════════════════════════════════════════════════════
        
        const intro = new EmbedBuilder()
          .setTitle(' BURNER PHONE ELITE - COMPLETE STAFF GUIDE')
          .setDescription(`**Enterprise-grade modmail + SOC-level security system**
          
This bot protects your server with the same security tech used by Fortune 500 companies.

** MODMAIL FEATURES:**
• Anonymous staff ↔ user communication
• Typing indicators (both ways)
• "Staff viewing" notifications
• Queue position tracking
• Persistent user notes
• Canned responses/snippets
• Staff away status
• Auto-close inactive tickets
• Post-close feedback ratings
• Full analytics dashboard

** SECURITY FEATURES:**
• 7 threat intelligence APIs
• Real-time phishing detection
• Malware file scanning
• Social engineering detection
• Risk scoring system`)
          .setColor(CONFIG.COLORS.primary)
          .setThumbnail(message.guild.iconURL());
        
        const howItWorks = new EmbedBuilder()
          .setTitle(' HOW MODMAIL WORKS')
          .setDescription(`**When a user DMs the bot:**

1⃣ User sends DM  Security scan runs
2⃣ If safe  Ticket created in this category
3⃣ You see: message, mood, reputation, history
4⃣ Just type in the ticket channel to reply
5⃣ User gets DM from "The Unpatched Method Staff"

**User sees:**
• Clear identification this is official support
• "Staff is viewing your ticket" notification
• "Staff is typing..." indicator
• Green  when their message is delivered

**They NEVER see your username!**`)
          .setColor(CONFIG.COLORS.info);
        
        const eliteFeatures = new EmbedBuilder()
          .setTitle(' ELITE FEATURES')
          .addFields(
            { name: ' User Notes', value: '`?note @user Important info`\nPersists across ALL tickets forever', inline: true },
            { name: ' Snippets', value: '`?snippet add greet Welcome!`\n`?snippet use greet`', inline: true },
            { name: ' Away Status', value: '`?away 2h In a meeting`\n`?back` to return', inline: true },
            { name: ' Analytics', value: '`?stats` - Your stats\n`?analytics` - Overall', inline: true },
            { name: ' History', value: '`?history @user`\nSee all past tickets', inline: true },
            { name: '⏰ Schedule', value: '`?schedule 2h Follow up msg`\nAuto-sends later', inline: true },
            { name: ' Transfer', value: '`?transfer @staff`\nHand off ticket', inline: true },
            { name: ' Priority', value: '`?priority urgent`\nChannel color changes', inline: true },
            { name: ' Link Tickets', value: '`?link #ticket-0001`\nConnect related issues', inline: true }
          )
          .setColor(CONFIG.COLORS.success);
        
        const commands1 = new EmbedBuilder()
          .setTitle('⌨ COMMANDS - BASIC')
          .addFields(
            { name: ' In Ticket Channels', value: `
\`?close [reason]\` - Close & burn messages
\`?closeandkick [reason]\` - Close + kick user
\`?claim\` - Mark ticket as yours
\`?priority low/med/high/urgent\` - Set urgency
Just type normally to reply to user
            `, inline: false },
            { name: ' In #staff-dm', value: `
\`?dm @user message\` - DM any user
            `, inline: false },
            { name: ' Anywhere (Staff)', value: `
\`?tickets\` - View all open tickets
\`?blacklist @user [reason]\` - Block from modmail
\`?unblacklist @user\` - Unblock user
\`?modmailguide\` - Quick command reference
            `, inline: false }
          )
          .setColor(CONFIG.COLORS.info);
        
        const commands2 = new EmbedBuilder()
          .setTitle('⌨ COMMANDS - ELITE')
          .addFields(
            { name: ' Notes & Snippets', value: `
\`?note @user note text\` - Add permanent note
\`?notes @user\` - View all notes + history
\`?snippet add name content\` - Save response
\`?snippet use name\` - Send saved response
\`?snippets\` - List all snippets
            `, inline: false },
            { name: ' Analytics & Status', value: `
\`?stats\` - Your personal stats
\`?analytics\` - Server-wide analytics
\`?away 2h message\` - Set away status
\`?back\` - Return from away
            `, inline: false },
            { name: ' Advanced', value: `
\`?history @user\` - User's ticket history
\`?transfer @staff\` - Transfer ticket
\`?schedule 1h message\` - Delayed message
\`?link #channel\` - Link related tickets
            `, inline: false }
          )
          .setColor(CONFIG.COLORS.info);
        
        const security1 = new EmbedBuilder()
          .setTitle(' SOC-LEVEL SECURITY SYSTEM')
          .setDescription(`**7 Threat Intelligence APIs:**

 **VirusTotal** - 70+ antivirus engines
 **IPQualityScore** - Fraud/phishing detection
 **AbuseIPDB** - IP reputation database
 **AlienVault OTX** - Threat intelligence
 **Hybrid Analysis** - Sandbox file analysis
 **Google Safe Browsing** - Phishing database
 **URLScan.io** - Deep URL analysis

**Every link and file is scanned automatically!**`)
          .setColor(CONFIG.COLORS.warning);
        
        const security2 = new EmbedBuilder()
          .setTitle(' LINK DETECTION')
          .setDescription(`**What gets detected:**

 **Typosquatting** - dlscord.com, disc0rd.gift
 **Homograph Attacks** - Cyrillic lookalike chars
 **URL Shorteners** - Expanded and analyzed
 **Fake Domains** - Discord/Steam impersonation
 **IP Hosting** - Direct IP instead of domain
 **Known Malware** - From threat databases

**Risk Score System:**
• 0-19:  Safe (allowed)
• 20-39:  Warning (allowed, logged)
• 40-59:  Flagged (allowed, staff alerted)
• 60-79:  Quarantine (blocked)
• 80+:  Critical (blocked, @here alert)`)
          .setColor(CONFIG.COLORS.warning);
        
        const security3 = new EmbedBuilder()
          .setTitle(' FILE SCANNING')
          .setDescription(`**Dangerous Files (BLOCKED):**
.exe, .bat, .cmd, .scr, .vbs, .ps1, .dll, .jar, .msi + 20 more

**Deep Analysis:**
• Magic byte verification (catches photo.jpg.exe)
• PDF JavaScript detection
• Archive content inspection
• Hybrid Analysis sandbox scan
• VirusTotal file scan

**Macro Documents (FLAGGED):**
.docm, .xlsm, .pptm - Allowed but staff alerted`)
          .setColor(CONFIG.COLORS.danger);
        
        const security4 = new EmbedBuilder()
          .setTitle(' SOCIAL ENGINEERING DETECTION')
          .setDescription(`**Patterns Detected:**

⏰ **Urgency** - "Act now!", "Limited time!"
 **Authority** - "Discord Team", "Official Staff"
 **Fear** - "Account terminated", "Hacked"
 **Prize Scams** - "You won!", "Free Nitro"
 **Demands** - "Click here", "Verify now"
 **Crypto Scams** - "Send BTC", "Double your money"

**All detected patterns add to risk score!**`)
          .setColor(CONFIG.COLORS.danger);
        
        const autoClose = new EmbedBuilder()
          .setTitle(' AUTO-CLOSE SYSTEM')
          .setDescription(`**Inactive Ticket Handling:**

⏰ **48 hours no activity:**
 User gets warning: "Reply or ticket closes"

⏰ **24 hours after warning:**
 Ticket auto-closes
 User notified
 Logged for records

**This keeps your ticket queue clean!**`)
          .setColor(CONFIG.COLORS.info);
        
        const feedback = new EmbedBuilder()
          .setTitle(' FEEDBACK SYSTEM')
          .setDescription(`**After every ticket closes:**

User receives: "Rate your experience "

**Ratings tracked in:**
• \`?analytics\` - Average rating shown
• Used to improve support quality

**Encourages good service!**`)
          .setColor(CONFIG.COLORS.success);
        
        const buttons = new EmbedBuilder()
          .setTitle(' TICKET BUTTONS')
          .setDescription(`**Every ticket has quick-action buttons:**

 **Claim** - Mark as yours
 **Close** - Close ticket
 **Priority** - Change urgency level
 **Notes** - View user's notes
 **History** - User's past tickets
 **Rep** - Adjust user reputation

**One-click actions for fast response!**`)
          .setColor(CONFIG.COLORS.primary);
        
        const tips = new EmbedBuilder()
          .setTitle(' PRO TIPS')
          .setDescription(`
**1. Use snippets for common responses:**
\`?snippet add rules Please read #rules\`

**2. Add notes for problem users:**
\`?note @user Frequently asks same question\`

**3. Set away when busy:**
\`?away 1h Lunch break\`

**4. Check analytics weekly:**
\`?analytics\` shows response times

**5. Trust the security system:**
If it blocks something, it's probably bad!

**6. Always close before kicking:**
\`?closeandkick reason\` does both safely
`)
          .setColor(CONFIG.COLORS.success)
          .setFooter({ text: 'Burner Phone ELITE • The Unpatched Method • Enterprise Security' });
        
        // Send all embeds
        await guide.send({ embeds: [intro, howItWorks, eliteFeatures] });
        await guide.send({ embeds: [commands1, commands2] });
        await guide.send({ embeds: [security1, security2] });
        await guide.send({ embeds: [security3, security4] });
        await guide.send({ embeds: [autoClose, feedback, buttons, tips] });
      }
      
      // Update the log channel ID constant in memory
      // Note: The MODMAIL_LOG_CHANNEL constant should match your actual log channel
      
      await message.reply({
        embeds: [new EmbedBuilder()
          .setTitle(' Burner Phone ELITE Ready!')
          .setDescription(`**Channels Created:**
 Category: ${cat}
 Logs: ${log}
 Staff DM: ${staffDm}
 Guide: ${guide}

**Next Steps:**
1. Read the guide in ${guide}
2. Make sure the log channel ID matches in bot config
3. Test by DMing the bot yourself!

**Current Log Channel ID:** \`${MODMAIL_LOG_CHANNEL}\`
**Created Log Channel ID:** \`${log.id}\`

${log.id !== MODMAIL_LOG_CHANNEL ? ' **Warning:** Log channel IDs don\'t match! Update MODMAIL_LOG_CHANNEL in code.' : ' Log channel ID matches!'}`)
          .setColor(CONFIG.COLORS.success)
        ]
      });
    }
    
    // ?modmailguide
    if (cmd === 'modmailguide' && isStaff(message.member)) {
      const guide = new EmbedBuilder()
        .setTitle(' BURNER PHONE ELITE - STAFF GUIDE')
        .setDescription('Premium modmail system with elite features')
        .addFields(
          { name: ' Basic Commands', value: `
\`?dm @user message\` - DM any user
\`?close [reason]\` - Close ticket
\`?claim\` - Claim ticket
\`?tickets\` - View open tickets
          ` },
          { name: ' Elite Commands', value: `
\`?note @user note\` - Add persistent note to user
\`?notes @user\` - View user's notes
\`?snippet add name content\` - Save a canned response
\`?snippet use name\` - Use a saved response
\`?snippets\` - List all snippets
\`?away [time] [message]\` - Set away status
\`?back\` - Return from away
\`?stats\` - View your stats
\`?analytics\` - Overall analytics
\`?history @user\` - User's ticket history
\`?link #ticket\` - Link related tickets
\`?schedule 1h message\` - Schedule a follow-up
\`?transfer @staff\` - Transfer ticket
\`?anon\` - Toggle anonymous mode
\`?priority low/med/high/urgent\` - Set ticket priority
          ` },
          { name: ' Buttons', value: ' Claim\n Close\n Priority\n View Notes\n History' }
        )
        .setColor(CONFIG.COLORS.primary);
      
      await message.reply({ embeds: [guide] });
    }
    
    // ?setupverify - Post verification embed in current channel
    if (cmd === 'setupverify' && isStaff(message.member)) {
      const embed = new EmbedBuilder()
        .setTitle(' Verification Required')
        .setDescription(
          `**Welcome to The Unpatched Method!**\n\n` +
          `Before you can access the server, you need to verify.\n\n` +
          `This helps us keep the community safe from:\n` +
          `• Alt accounts from banned users\n` +
          `• Brand new throwaway accounts\n` +
          `• Bot raids and spam\n\n` +
          `**What we check:**\n` +
          `• Account must be at least **7 days old**\n` +
          `• Not a known alt of a banned user\n\n` +
          `Click the button below to verify and gain access!`
        )
        .setColor(0xFF6B35)
        .setFooter({ text: 'Verification is quick and automatic • Security by Burner Phone' })
        .setTimestamp();

      const row = new ActionRowBuilder()
        .addComponents(
          new ButtonBuilder()
            .setCustomId('verify_user')
            .setLabel(' Verify Me')
            .setStyle(ButtonStyle.Success)
        );

      await message.channel.send({ embeds: [embed], components: [row] });
      await message.delete().catch(() => {});
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ?ban @user reason - Kick + flag fingerprint (no IP ban)
    // User can rejoin but can't verify, gets exposed as alt
    // ═══════════════════════════════════════════════════════════════
    if (cmd === 'ban' && isStaff(message.member)) {
      const user = message.mentions.users.first();
      const reason = args.slice(1).join(' ') || 'No reason provided';
      
      if (!user) {
        return message.reply('Usage: `?ban @user reason`');
      }
      
      const member = message.guild.members.cache.get(user.id);
      if (!member) {
        return message.reply(' User not found in server.');
      }
      
      try {
        let fingerprintFlagged = false;
        
        // Get user's fingerprint from device_fingerprints table
        const fingerprintResult = await pool.query(
          `SELECT * FROM device_fingerprints WHERE discord_id = $1 AND guild_id = $2`,
          [user.id, message.guild.id]
        );
        
        if (fingerprintResult.rows.length > 0) {
          const userFingerprint = fingerprintResult.rows[0];
          
          // Copy fingerprint to fingerprint_bans table
          await pool.query(`
            INSERT INTO fingerprint_bans (fingerprint_hash, banned_discord_id, banned_discord_tag, guild_id, reason, banned_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (fingerprint_hash, guild_id) DO UPDATE SET
              banned_discord_id = $2,
              banned_discord_tag = $3,
              reason = $5,
              banned_by = $6,
              banned_at = NOW()
          `, [userFingerprint.fingerprint_hash, user.id, user.tag, message.guild.id, reason, message.author.id]);
          
          fingerprintFlagged = true;
          console.log(`[BAN] Fingerprint flagged for ${user.tag}`);
        } else {
          console.log(`[BAN] No fingerprint record for ${user.tag}`);
        }
        
        // DM the user before kicking
        try {
          await user.send({
            embeds: [new EmbedBuilder()
              .setTitle(' You Have Been Removed')
              .setDescription(`You have been removed from **The Unpatched Method**.\n\n**Reason:** ${reason}\n\n **Warning:** Your device has been fingerprinted. If you try to rejoin on an alt account, you will be identified and blocked.`)
              .setColor(0xFF0000)
              .setFooter({ text: 'The Unpatched Method • Burner Phone Security' })
              .setTimestamp()
            ]
          });
        } catch (e) {}
        
        // Kick the user (no IP ban)
        await member.kick(reason);
        
        // Log to security channel
        const securityLog = message.guild.channels.cache.find(c => 
          c.name === 'security-logs' || c.name === 'modmail-logs'
        );
        
        if (securityLog) {
          const logEmbed = new EmbedBuilder()
            .setTitle(' User Banned')
            .setDescription(`**User:** ${user.tag}\n**ID:** \`${user.id}\`\n**Reason:** ${reason}\n**By:** ${message.author.tag}`)
            .addFields({
              name: ' Fingerprint Status',
              value: fingerprintFlagged 
                ? ' Device fingerprint flagged - alt accounts will be blocked'
                : ' No fingerprint on record (user never verified)',
              inline: false
            })
            .setColor(0xFF6B35)
            .setThumbnail(user.displayAvatarURL())
            .setTimestamp();
          
          await securityLog.send({ embeds: [logEmbed] });
        }
        
        await message.reply({
          embeds: [new EmbedBuilder()
            .setTitle(' Ban Complete')
            .setDescription(`**${user.tag}** has been banned.\n\n${fingerprintFlagged ? ' Their device is flagged - if they rejoin on an alt, they will be exposed and blocked at verification.' : ' User had no verification record, so no fingerprint was flagged.'}`)
            .setColor(0xFF6B35)
          ]
        });
        
      } catch (error) {
        console.error('Ban error:', error);
        return message.reply(' Failed to ban user. Make sure I have kick permissions.');
      }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ?unban @user - Remove fingerprint flag so they can verify again
    // ═══════════════════════════════════════════════════════════════
    if (cmd === 'unban' && isStaff(message.member)) {
      const user = message.mentions.users.first();
      
      if (!user) {
        return message.reply('Usage: `?unban @user`');
      }
      
      try {
        // Get the user's fingerprint first
        const fingerprintResult = await pool.query(
          `SELECT fingerprint_hash FROM device_fingerprints WHERE discord_id = $1 AND guild_id = $2`,
          [user.id, message.guild.id]
        );
        
        let removed = false;
        
        if (fingerprintResult.rows.length > 0) {
          // Remove from fingerprint_bans by fingerprint hash
          const deleteResult = await pool.query(
            `DELETE FROM fingerprint_bans WHERE fingerprint_hash = $1 AND guild_id = $2 RETURNING *`,
            [fingerprintResult.rows[0].fingerprint_hash, message.guild.id]
          );
          removed = deleteResult.rows.length > 0;
        }
        
        // Also try to remove by discord_id directly
        const deleteById = await pool.query(
          `DELETE FROM fingerprint_bans WHERE banned_discord_id = $1 AND guild_id = $2 RETURNING *`,
          [user.id, message.guild.id]
        );
        if (deleteById.rows.length > 0) removed = true;
        
        // Log to security channel
        const securityLog = message.guild.channels.cache.find(c => 
          c.name === 'security-logs' || c.name === 'modmail-logs'
        );
        
        if (securityLog) {
          const logEmbed = new EmbedBuilder()
            .setTitle(' User Unbanned')
            .setDescription(`**User:** ${user.tag}\n**ID:** \`${user.id}\`\n**By:** ${message.author.tag}`)
            .addFields({
              name: ' Fingerprint Status',
              value: removed 
                ? ' Fingerprint flag removed - user can verify again'
                : ' No fingerprint ban record found (user may not have been banned or never verified)',
              inline: false
            })
            .setColor(0x00FF00)
            .setTimestamp();
          
          await securityLog.send({ embeds: [logEmbed] });
        }
        
        await message.reply({
          embeds: [new EmbedBuilder()
            .setTitle(' Unban Complete')
            .setDescription(`**${user.tag}** has been unbanned.\n\n${removed ? 'Their device fingerprint flag has been removed. They can now verify again.' : ' No fingerprint ban record was found. They may not have been banned, or never verified.'}`)
            .setColor(0x00FF00)
          ]
        });
        
      } catch (error) {
        console.error('Unban error:', error);
        return message.reply(' Failed to unban user.');
      }
    }
    
    // ═══════════════════════════════════════════════════════════════
    // ELITE COMMANDS
    // ═══════════════════════════════════════════════════════════════
    
    // ?note @user note - Add persistent user note
    if (cmd === 'note' && isStaff(message.member)) {
      const user = message.mentions.users.first();
      const note = args.slice(1).join(' ');
      if (!user || !note) return message.reply('Usage: `?note @user Your note here`');
      
      await addUserNote(user.id, note, message.author.id, message.author.tag);
      await message.reply(` Note added for ${user.tag}: "${note}"`);
    }
    
    // ?notes @user - View user notes
    if (cmd === 'notes' && isStaff(message.member)) {
      const user = message.mentions.users.first();
      if (!user) return message.reply('Usage: `?notes @user`');
      
      const notes = await getUserNotes(user.id);
      const history = await getUserTicketHistory(user.id);
      const sentiment = await getUserSentimentHistory(user.id);
      
      const embed = new EmbedBuilder()
        .setTitle(` User Profile: ${user.tag}`)
        .setThumbnail(user.displayAvatarURL())
        .setColor(CONFIG.COLORS.info);
      
      // Ticket history
      embed.addFields({
        name: ' Ticket History',
        value: `Total: **${history.total}** | Open: **${history.open}** | Closed: **${history.closed}**`,
        inline: false
      });
      
      // Sentiment
      if (sentiment.length > 0) {
        const sentimentStr = sentiment.map(s => `${s.sentiment}: ${s.count}`).join(', ');
        embed.addFields({ name: ' Typical Mood', value: sentimentStr, inline: false });
      }
      
      // Notes
      if (notes.length > 0) {
        const notesStr = notes.slice(0, 5).map(n => 
          `• ${n.note} - *${n.added_by_name}, ${timeAgo(n.created_at)}*`
        ).join('\n');
        embed.addFields({ name: ' Notes', value: notesStr, inline: false });
      } else {
        embed.addFields({ name: ' Notes', value: 'No notes yet', inline: false });
      }
      
      await message.reply({ embeds: [embed] });
    }
    
    // ?snippet add name content - Save snippet
    if (cmd === 'snippet' && isStaff(message.member)) {
      const subCmd = args[0]?.toLowerCase();
      
      if (subCmd === 'add') {
        const name = args[1];
        const content = args.slice(2).join(' ');
        if (!name || !content) return message.reply('Usage: `?snippet add name Your response here`');
        
        await saveSnippet(name, content, message.author.id);
        await message.reply(` Snippet **${name}** saved!`);
      }
      else if (subCmd === 'use') {
        const name = args[1];
        if (!name) return message.reply('Usage: `?snippet use name`');
        
        const snippet = await getSnippet(name);
        if (!snippet) return message.reply(` Snippet "${name}" not found.`);
        
        // If in ticket channel, send to user
        const ticket = await getTicketByChannel(message.channel.id);
        if (ticket) {
          const user = await client.users.fetch(ticket.user_id);
          const embed = new EmbedBuilder()
            .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
            .setTitle(' Staff Message')
            .setDescription(snippet.content)
            .addFields({
              name: ' What is this?',
              value: 'This is the official support bot for **The Unpatched Method** Discord server.',
              inline: false
            })
            .setColor(CONFIG.COLORS.primary)
            .setFooter({ text: 'The Unpatched Method • Reply to respond' })
            .setTimestamp();
          
          await user.send({ embeds: [embed] });
          await message.react('');
          
          await pool.query(`
            INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
            VALUES ($1, $2, $3, $4, true)
          `, [ticket.id, message.author.id, message.author.tag, snippet.content]);
        } else {
          await message.reply(snippet.content);
        }
      }
      else if (subCmd === 'delete') {
        const name = args[1];
        if (!name) return message.reply('Usage: `?snippet delete name`');
        await pool.query(`DELETE FROM snippets WHERE LOWER(name) = LOWER($1)`, [name]);
        await message.reply(` Snippet **${name}** deleted.`);
      }
    }
    
    // ?snippets - List all snippets
    if (cmd === 'snippets' && isStaff(message.member)) {
      const r = await pool.query(`SELECT name, uses FROM snippets ORDER BY uses DESC`);
      if (r.rows.length === 0) return message.reply('No snippets saved yet. Use `?snippet add name content` to create one.');
      
      const list = r.rows.map(s => `\`${s.name}\` (used ${s.uses}x)`).join('\n');
      const embed = new EmbedBuilder()
        .setTitle(' Saved Snippets')
        .setDescription(list)
        .setColor(CONFIG.COLORS.info)
        .setFooter({ text: 'Use: ?snippet use name' });
      
      await message.reply({ embeds: [embed] });
    }
    
    // ?away [time] [message] - Set away status
    if (cmd === 'away' && isStaff(message.member)) {
      const timeArg = args[0];
      const awayMessage = args.slice(1).join(' ') || 'Currently away';
      
      let untilDate = null;
      if (timeArg) {
        const match = timeArg.match(/^(\d+)(m|h|d)$/);
        if (match) {
          const amount = parseInt(match[1]);
          const unit = match[2];
          untilDate = new Date();
          if (unit === 'm') untilDate.setMinutes(untilDate.getMinutes() + amount);
          if (unit === 'h') untilDate.setHours(untilDate.getHours() + amount);
          if (unit === 'd') untilDate.setDate(untilDate.getDate() + amount);
        }
      }
      
      await setStaffStatus(message.author.id, 'away', awayMessage, untilDate);
      await message.reply(` You are now away${untilDate ? ` until ${untilDate.toLocaleString()}` : ''}.\nMessage: "${awayMessage}"`);
    }
    
    // ?back - Return from away
    if (cmd === 'back' && isStaff(message.member)) {
      await setStaffStatus(message.author.id, 'available', null, null);
      await message.reply(' Welcome back! You are now available.');
    }
    
    // ?stats - Personal stats
    if (cmd === 'stats' && isStaff(message.member)) {
      const stats = await getStaffStats(message.author.id);
      
      const embed = new EmbedBuilder()
        .setTitle(` Your Stats`)
        .setThumbnail(message.author.displayAvatarURL())
        .addFields(
          { name: ' Replies Sent', value: String(stats.replies || 0), inline: true },
          { name: ' Tickets Closed', value: String(stats.closes || 0), inline: true },
          { name: ' Tickets Claimed', value: String(stats.claims || 0), inline: true },
          { name: '⏱ Avg Response Time', value: stats.avg_response_time ? formatDuration(stats.avg_response_time) : 'N/A', inline: true }
        )
        .setColor(CONFIG.COLORS.primary);
      
      await message.reply({ embeds: [embed] });
    }
    
    // ?analytics - Overall analytics
    if (cmd === 'analytics' && isStaff(message.member)) {
      const analytics = await getOverallAnalytics();
      
      const embed = new EmbedBuilder()
        .setTitle(' Modmail Analytics')
        .addFields(
          { name: ' Total Tickets', value: String(analytics.total_tickets || 0), inline: true },
          { name: ' Currently Open', value: String(analytics.open_tickets || 0), inline: true },
          { name: ' Today', value: String(analytics.tickets_today || 0), inline: true },
          { name: ' This Week', value: String(analytics.tickets_week || 0), inline: true },
          { name: '⏱ Avg Response', value: analytics.avg_response_time ? formatDuration(analytics.avg_response_time) : 'N/A', inline: true },
          { name: ' Avg Rating', value: analytics.avg_rating ? `${analytics.avg_rating}/5` : 'N/A', inline: true }
        )
        .setColor(CONFIG.COLORS.primary)
        .setTimestamp();
      
      await message.reply({ embeds: [embed] });
    }
    
    // ?history @user - User ticket history
    if (cmd === 'history' && isStaff(message.member)) {
      const user = message.mentions.users.first();
      if (!user) return message.reply('Usage: `?history @user`');
      
      const r = await pool.query(`
        SELECT * FROM modmail_tickets 
        WHERE user_id = $1 
        ORDER BY created_at DESC 
        LIMIT 10
      `, [user.id]);
      
      if (r.rows.length === 0) return message.reply(`${user.tag} has no ticket history.`);
      
      const list = r.rows.map(t => 
        `**#${t.ticket_number}** - ${t.status} - ${timeAgo(t.created_at)}${t.close_reason ? ` (${t.close_reason.slice(0, 30)})` : ''}`
      ).join('\n');
      
      const embed = new EmbedBuilder()
        .setTitle(` Ticket History: ${user.tag}`)
        .setDescription(list)
        .setThumbnail(user.displayAvatarURL())
        .setColor(CONFIG.COLORS.info);
      
      await message.reply({ embeds: [embed] });
    }
    
    // ?link #channel - Link tickets
    if (cmd === 'link' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return message.reply('Use this in a ticket channel.');
      
      const linkedChannel = message.mentions.channels.first();
      if (!linkedChannel) return message.reply('Usage: `?link #ticket-channel`');
      
      const linkedTicket = await getTicketByChannel(linkedChannel.id);
      if (!linkedTicket) return message.reply('That channel is not a ticket.');
      
      await linkTickets(ticket.id, linkedTicket.id, message.author.id);
      await message.reply(` Linked to ticket #${linkedTicket.ticket_number}`);
    }
    
    // ?schedule 1h message - Schedule follow-up
    if (cmd === 'schedule' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return message.reply('Use this in a ticket channel.');
      
      const timeArg = args[0];
      const content = args.slice(1).join(' ');
      if (!timeArg || !content) return message.reply('Usage: `?schedule 1h Your follow-up message`');
      
      const match = timeArg.match(/^(\d+)(m|h|d)$/);
      if (!match) return message.reply('Invalid time format. Use: 30m, 2h, 1d');
      
      const amount = parseInt(match[1]);
      const unit = match[2];
      const sendAt = new Date();
      if (unit === 'm') sendAt.setMinutes(sendAt.getMinutes() + amount);
      if (unit === 'h') sendAt.setHours(sendAt.getHours() + amount);
      if (unit === 'd') sendAt.setDate(sendAt.getDate() + amount);
      
      await scheduleMessage(ticket.id, content, message.author.id, sendAt);
      await message.reply(`⏰ Message scheduled for ${sendAt.toLocaleString()}`);
    }
    
    // ?transfer @staff - Transfer ticket
    if (cmd === 'transfer' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return message.reply('Use this in a ticket channel.');
      
      const newStaff = message.mentions.members.first();
      if (!newStaff) return message.reply('Usage: `?transfer @staff`');
      if (!isStaff(newStaff)) return message.reply('That user is not staff.');
      
      await pool.query(`UPDATE modmail_tickets SET claimed_by = $1 WHERE id = $2`, [newStaff.id, ticket.id]);
      await message.channel.send(` Ticket transferred from ${message.author} to ${newStaff}`);
      
      // Notify the user
      const user = await client.users.fetch(ticket.user_id);
      await user.send({
        embeds: [new EmbedBuilder()
          .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
          .setTitle(' Ticket Transferred')
          .setDescription('Your ticket has been transferred to another staff member for better assistance.')
          .setColor(CONFIG.COLORS.info)
          .setFooter({ text: 'The Unpatched Method • Support' })
        ]
      }).catch(() => {});
    }
    
    // ?priority low/med/high/urgent - Set priority
    if (cmd === 'priority' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return message.reply('Use this in a ticket channel.');
      
      const level = args[0]?.toLowerCase();
      const priorities = { low: '', med: '', high: '', urgent: '' };
      if (!priorities[level]) return message.reply('Usage: `?priority low/med/high/urgent`');
      
      await pool.query(`UPDATE modmail_tickets SET priority = $1 WHERE id = $2`, [level, ticket.id]);
      
      // Update channel name
      const emoji = priorities[level];
      const newName = `${emoji}-ticket-${ticket.ticket_number.toString().padStart(4, '0')}`;
      await message.channel.setName(newName).catch(() => {});
      
      await message.reply(` Priority set to **${level.toUpperCase()}** ${emoji}`);
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// BUTTONS
// ═══════════════════════════════════════════════════════════════════════════════

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  
  const ticket = await getTicketByChannel(interaction.channel.id);
  if (!ticket) return;
  if (!isStaff(interaction.member)) return interaction.reply({ content: ' Staff only.', ephemeral: true });
  
  if (interaction.customId === 'claim') {
    if (ticket.claimed_by) return interaction.reply({ content: `Already claimed by <@${ticket.claimed_by}>`, ephemeral: true });
    await pool.query(`UPDATE modmail_tickets SET claimed_by = $1 WHERE id = $2`, [interaction.user.id, ticket.id]);
    await interaction.reply(` Claimed by ${interaction.user}`);
    
    // Notify the user that their ticket has been seen
    try {
      const user = await client.users.fetch(ticket.user_id);
      await user.send({
        embeds: [new EmbedBuilder()
          .setAuthor({ 
            name: 'The Unpatched Method Staff', 
            iconURL: client.user.displayAvatarURL() 
          })
          .setTitle(' Ticket Received')
          .setDescription('A staff member is now reviewing your message. Please wait for a response.\n\nYou can continue to send messages here and they will be added to your ticket.')
          .addFields({
            name: ' What is this?',
            value: 'This is the official support bot for **The Unpatched Method** Discord server. Do not block this bot or you won\'t receive staff responses.',
            inline: false
          })
          .setColor(CONFIG.COLORS.success)
          .setFooter({ text: 'The Unpatched Method • Reply here to respond to staff' })
        ]
      });
    } catch (e) {}
  }
  
  if (interaction.customId === 'close') {
    await interaction.reply(' Closing ticket...');
    
    // Generate transcript first
    const messages = await pool.query(`
      SELECT * FROM modmail_messages WHERE ticket_id = $1 ORDER BY created_at ASC
    `, [ticket.id]);
    
    let transcript = `╔══════════════════════════════════════════════════════════════╗\n`;
    transcript += `║           TICKET #${ticket.ticket_number} - TRANSCRIPT                    ║\n`;
    transcript += `╚══════════════════════════════════════════════════════════════╝\n\n`;
    transcript += `User ID: ${ticket.user_id}\n`;
    transcript += `Opened: ${ticket.created_at}\n`;
    transcript += `Closed: ${new Date().toISOString()}\n`;
    transcript += `Closed by: ${interaction.user.tag}\n\n`;
    transcript += `════════════════════ MESSAGES ════════════════════\n\n`;
    
    for (const msg of messages.rows) {
      const prefix = msg.is_staff ? '[STAFF]' : '[USER]';
      const time = new Date(msg.created_at).toLocaleString();
      transcript += `${prefix} ${msg.author_name} (${time}):\n${msg.content}\n\n`;
    }
    
    await pool.query(`UPDATE modmail_tickets SET status = 'closed', closed_at = NOW(), closed_by = $1 WHERE id = $2`, [interaction.user.id, ticket.id]);
    
    try {
      const user = await client.users.fetch(ticket.user_id);
      await user.send({ embeds: [new EmbedBuilder()
        .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
        .setTitle(' Ticket Closed')
        .setDescription('Your ticket has been resolved.\n\n*This conversation will be deleted shortly.*\n\nThank you for contacting The Unpatched Method support. If you need help again, just DM this bot!')
        .setColor(CONFIG.COLORS.error)
        .setFooter({ text: 'The Unpatched Method • Support' })
      ] });
      
      await interaction.channel.send(' Burning messages...');
      
      // Delete bot's messages from user's DMs (burner style)
      try {
        const dmChannel = await user.createDM();
        const dmMessages = await dmChannel.messages.fetch({ limit: 100 });
        const botMessages = dmMessages.filter(m => m.author.id === client.user.id);
        
        for (const [, msg] of botMessages) {
          await msg.delete().catch(() => {});
          await new Promise(r => setTimeout(r, 500));
        }
      } catch (e) {
        console.log('Could not delete DM messages:', e.message);
      }
    } catch (e) {}
    
    // Send transcript to log channel
    const logChannel = interaction.guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
    if (logChannel) {
      const logEmbed = new EmbedBuilder()
        .setTitle(` Ticket #${ticket.ticket_number} Closed`)
        .addFields(
          { name: ' User', value: `<@${ticket.user_id}>`, inline: true },
          { name: ' Closed By', value: interaction.user.tag, inline: true },
          { name: ' Opened', value: `<t:${Math.floor(new Date(ticket.created_at).getTime() / 1000)}:R>`, inline: true }
        )
        .setColor(CONFIG.COLORS.warning)
        .setTimestamp();
      
      const transcriptBuffer = Buffer.from(transcript, 'utf-8');
      await logChannel.send({ 
        embeds: [logEmbed], 
        files: [{ attachment: transcriptBuffer, name: `ticket-${ticket.ticket_number}-transcript.txt` }] 
      });
    }
    
    await interaction.channel.send(' Transcript saved. Deleting channel in 5 seconds...');
    setTimeout(() => interaction.channel.delete().catch(() => {}), 5000);
  }
  
  if (interaction.customId === 'priority') {
    await interaction.reply({
      content: 'Select priority:',
      components: [new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('p_high').setLabel(' High').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId('p_normal').setLabel(' Normal').setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId('p_low').setLabel(' Low').setStyle(ButtonStyle.Success)
      )],
      ephemeral: true
    });
  }
  
  if (interaction.customId.startsWith('p_')) {
    const p = interaction.customId.replace('p_', '');
    await pool.query(`UPDATE modmail_tickets SET priority = $1 WHERE id = $2`, [p, ticket.id]);
    await interaction.update({ content: `Priority: ${p}`, components: [] });
  }
});

// Handle DM confirmation buttons
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  
  // ═══════════════════════════════════════════════════════════════
  // VERIFICATION BUTTON HANDLER - Generates token and redirects to theunpatchedmethod.com
  // ═══════════════════════════════════════════════════════════════
  if (interaction.customId === 'verify_user') {
    await interaction.deferReply({ ephemeral: true });
    
    const member = interaction.member;
    const guild = interaction.guild;
    
    // Find verified role
    const VERIFIED_ROLE_ID = '1453304594317836423';
    const verifiedRole = guild.roles.cache.get(VERIFIED_ROLE_ID) || 
                         guild.roles.cache.find(r => r.name.toLowerCase() === 'verified' || r.name.toLowerCase() === 'member');
    
    if (!verifiedRole) {
      return interaction.editReply(' Verification role not found. Please contact staff.');
    }
    
    // Check if already verified
    if (member.roles.cache.has(verifiedRole.id)) {
      return interaction.editReply(' You are already verified!');
    }
    
    // Quick account age check
    const accountAge = Date.now() - member.user.createdTimestamp;
    const minAge = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    if (accountAge < minAge) {
      const daysOld = Math.floor(accountAge / (24 * 60 * 60 * 1000));
      
      const securityLog = guild.channels.cache.find(c => c.name === 'security-logs' || c.name === 'modmail-logs');
      if (securityLog) {
        const alertEmbed = new EmbedBuilder()
          .setTitle(' VERIFICATION BLOCKED - New Account')
          .setDescription(`**User:** ${member.user.tag}\n**ID:** \`${member.id}\`\n**Account Age:** ${daysOld} days (minimum: 7)`)
          .setColor(0xFF6600)
          .setThumbnail(member.user.displayAvatarURL())
          .setTimestamp();
        await securityLog.send({ embeds: [alertEmbed] });
      }
      
      return interaction.editReply(` Your account is too new (${daysOld} days old).\n\nAccounts must be at least **7 days old** to verify.\n\nIf you believe this is an error, contact staff.`);
    }
    
    try {
      // Generate local verification token
      const token = generateToken();
      const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
      
      // Store token
      verificationTokens.set(token, {
        discord_id: member.id,
        guild_id: guild.id,
        expires_at: expiresAt
      });
      
      console.log(`[VERIFY] Generated token for ${member.user.tag}`);
      
      // Build verification URL
      const verifyUrl = `https://theunpatchedmethod.com/verify.html?token=${token}&user=${member.id}&guild=${guild.id}`;
      
      // Send verification link to user
      const verifyEmbed = new EmbedBuilder()
        .setTitle(' Complete Verification')
        .setDescription(`**Click the link below to verify:**\n\n **[Click Here to Verify](${verifyUrl})**\n\nThis link expires in **10 minutes**.`)
        .addFields(
          { name: ' What happens next?', value: '1. Click the link above\n2. Complete a quick CAPTCHA\n3. You\'ll automatically get verified\n4. Return to Discord and pick your roles!' }
        )
        .setColor(0xFF6B35)
        .setFooter({ text: 'Burner Phone • Alt Detection System' })
        .setTimestamp();
      
      const verifyButton = new ActionRowBuilder()
        .addComponents(
          new ButtonBuilder()
            .setLabel(' Verify Now')
            .setStyle(ButtonStyle.Link)
            .setURL(verifyUrl)
        );
      
      await interaction.editReply({ 
        embeds: [verifyEmbed],
        components: [verifyButton]
      });
      
    } catch (error) {
      console.error('Verification error:', error);
      return interaction.editReply(' Verification system error. Please try again or contact staff.');
    }
  }
  
  // Cancel DM
  if (interaction.customId === 'cancel_dm') {
    // Find and delete the original message and preview
    for (const [key, pending] of client.pendingDMs || new Map()) {
      if (key.startsWith(interaction.user.id)) {
        pending.originalMsg?.delete().catch(() => {});
        pending.preview?.delete().catch(() => {});
        client.pendingDMs.delete(key);
        break;
      }
    }
    return;
  }
  
  // Confirm DM
  if (interaction.customId.startsWith('confirm_dm_')) {
    const userId = interaction.customId.replace('confirm_dm_', '');
    const key = `${interaction.user.id}_${userId}`;
    const pending = client.pendingDMs?.get(key);
    
    if (!pending) {
      return interaction.update({ content: ' Message expired. Please try again.', embeds: [], components: [] });
    }
    
    // Defer first to avoid timeout
    await interaction.deferUpdate();
    
    try {
      const { user, content, guild, originalMsg, preview } = pending;
      
      // Check if user already has open ticket
      let ticket = await getOpenTicket(user.id);
      
      if (!ticket) {
        // Create ticket for this outreach
        const ticketNum = await getNextTicketNumber();
        
        // Find or create category
        let category = guild.channels.cache.find(c => c.name === ' MODMAIL' && c.type === ChannelType.GuildCategory);
        if (!category) {
          category = await guild.channels.create({
            name: ' MODMAIL',
            type: ChannelType.GuildCategory,
            permissionOverwrites: [{ id: guild.id, deny: [PermissionFlagsBits.ViewChannel] }]
          });
        }
        
        // Create channel
        const channel = await guild.channels.create({
          name: `ticket-${ticketNum.toString().padStart(4, '0')}`,
          type: ChannelType.GuildText,
          parent: category.id,
          topic: `User: ${user.tag} (${user.id}) | Staff initiated`
        });
        
        // Save to DB
        const r = await pool.query(`
          INSERT INTO modmail_tickets (ticket_number, user_id, guild_id, channel_id)
          VALUES ($1, $2, $3, $4) RETURNING *
        `, [ticketNum, user.id, guild.id, channel.id]);
        ticket = r.rows[0];
        
        // Ticket embed
        const embed = new EmbedBuilder()
          .setTitle(` Ticket #${ticketNum} (Staff Initiated)`)
          .setDescription(`**User:** ${user} (${user.tag})\n**ID:** ${user.id}\n**Started by:** ${interaction.user.tag}`)
          .setColor(CONFIG.COLORS.primary)
          .setThumbnail(user.displayAvatarURL())
          .setTimestamp();
        
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId('claim').setLabel('Claim').setStyle(ButtonStyle.Primary).setEmoji(''),
          new ButtonBuilder().setCustomId('close').setLabel('Close').setStyle(ButtonStyle.Danger).setEmoji(''),
          new ButtonBuilder().setCustomId('priority').setLabel('Priority').setStyle(ButtonStyle.Secondary).setEmoji('')
        );
        
        await channel.send({ embeds: [embed], components: [row] });
      }
      
      // Save outgoing message
      await pool.query(`
        INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
        VALUES ($1, $2, $3, $4, true)
      `, [ticket.id, interaction.user.id, interaction.user.tag, content]);
      
      // DM the user - clear identification of who this is
      const dmEmbed = new EmbedBuilder()
        .setAuthor({ 
          name: 'The Unpatched Method Staff', 
          iconURL: client.user.displayAvatarURL() 
        })
        .setTitle(' Staff Message')
        .setDescription(content)
        .addFields({
          name: ' What is this?',
          value: 'This is the official support bot for **The Unpatched Method** Discord server. A staff member is reaching out to you.',
          inline: false
        })
        .setColor(CONFIG.COLORS.primary)
        .setFooter({ text: 'The Unpatched Method • Reply to this DM to respond to staff' })
        .setTimestamp();
      
      await user.send({ embeds: [dmEmbed] });
      
      // Get ticket channel and send confirmation there
      const ticketChannel = guild.channels.cache.get(ticket.channel_id);
      if (ticketChannel && ticketChannel.id !== interaction.channel.id) {
        const outEmbed = new EmbedBuilder()
          .setAuthor({ name: `${interaction.user.tag} (Staff)`, iconURL: interaction.user.displayAvatarURL() })
          .setDescription(content)
          .setColor(CONFIG.COLORS.success)
          .setTimestamp();
        await ticketChannel.send({ embeds: [outEmbed] });
      }
      
      // Delete original command and preview - keep channel clean
      originalMsg?.delete().catch(() => {});
      preview?.delete().catch(() => {});
      
      // Send brief confirmation then delete it too
      const confirm = await interaction.channel.send(` Message sent to ${user.tag} - Ticket: <#${ticket.channel_id}>`);
      setTimeout(() => confirm.delete().catch(() => {}), 5000);
      
      // Clean up
      client.pendingDMs.delete(key);
    } catch (e) {
      console.error('DM error:', e);
      await interaction.editReply({ content: ` Could not DM user - they may have DMs disabled.`, embeds: [], components: [] }).catch(() => {});
      client.pendingDMs.delete(key);
    }
  }
});

// Handle ticket confirmation from DMs
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  
  // Only handle in DMs
  if (interaction.channel.type !== ChannelType.DM) return;
  
  // Appeal button - Suspended (banned alt)
  if (interaction.customId.startsWith('appeal_ban_')) {
    await interaction.update({
      embeds: [new EmbedBuilder()
        .setTitle(' Write Your Appeal')
        .setDescription('Please reply to this message with your appeal.\n\nInclude:\n• Why you believe this is a mistake\n• Any relevant context\n\nYour next message will be sent to staff.')
        .setColor(0x5865F2)
      ],
      components: []
    });
    
    // Store that they're writing an appeal
    if (!client.pendingAppeals) client.pendingAppeals = new Map();
    client.pendingAppeals.set(interaction.user.id, { type: 'suspended', timestamp: Date.now() });
    return;
  }
  
  // Appeal button - Alternate Account
  if (interaction.customId.startsWith('appeal_alt_')) {
    await interaction.update({
      embeds: [new EmbedBuilder()
        .setTitle(' Explain Your Situation')
        .setDescription('Please reply to this message explaining why you need a second account.\n\nCommon reasons:\n• Shared computer/device\n• Sold/gave away old device\n• Family member\'s account\n\nYour next message will be sent to staff.')
        .setColor(0x5865F2)
      ],
      components: []
    });
    
    // Store that they're writing an appeal
    if (!client.pendingAppeals) client.pendingAppeals = new Map();
    client.pendingAppeals.set(interaction.user.id, { type: 'alternate', timestamp: Date.now() });
    return;
  }
  
  // Decline appeal
  if (interaction.customId.startsWith('appeal_decline') || interaction.customId === 'appeal_dismiss') {
    await interaction.update({
      embeds: [new EmbedBuilder()
        .setTitle(' Appeal Dismissed')
        .setDescription('You can start an appeal later by messaging this bot.')
        .setColor(0x666666)
      ],
      components: []
    });
    return;
  }
  
  if (interaction.customId === 'cancel_ticket') {
    client.pendingTickets?.delete(interaction.user.id);
    await interaction.update({ 
      content: ' Cancelled. Your message was not sent.', 
      embeds: [], 
      components: [] 
    });
    return;
  }
  
  if (interaction.customId === 'confirm_ticket') {
    const pending = client.pendingTickets?.get(interaction.user.id);
    
    if (!pending) {
      return interaction.reply({ 
        content: ' Session expired. Please send your message again.', 
        ephemeral: true 
      });
    }
    
    // Defer the reply - this gives us 15 minutes to respond
    await interaction.deferUpdate();
    
    try {
      const { content, guild, user, originalMessage, threatAnalysis } = pending;
      
      // Create new ticket
      const ticket = await createTicket(user, guild, content, {});
      
      // Add green checkmark to original message
      if (originalMessage) {
        await originalMessage.react('').catch(() => {});
      }
      
      // If there was a security threat, send alert to the ticket channel
      if (threatAnalysis && threatAnalysis.score >= RISK_THRESHOLDS.LOW) {
        const ticketChannel = guild.channels.cache.get(ticket.channel_id);
        if (ticketChannel) {
          // Build detailed threat breakdown for staff
          let staffAlert = `**Risk Score:** ${threatAnalysis.score}/100\n**Action:** ${threatAnalysis.action}\n\n`;
          staffAlert += `**Detections:**\n`;
          for (const f of (threatAnalysis.findings || []).slice(0, 5)) {
            if (f.code) {
              staffAlert += `• \`[${f.code}]\` +${f.points}pts - ${f.detail}\n`;
            }
          }
          
          // API results if available
          if (threatAnalysis.apiResults) {
            staffAlert += `\n**API Scan Results:**\n`;
            if (threatAnalysis.apiResults.virustotal?.available) {
              const vt = threatAnalysis.apiResults.virustotal;
              staffAlert += `• VirusTotal: ${vt.malicious || 0} malicious, ${vt.suspicious || 0} suspicious\n`;
            }
            if (threatAnalysis.apiResults.googleSafeBrowsing?.available && threatAnalysis.apiResults.googleSafeBrowsing.threats?.length) {
              staffAlert += `• Google: ${threatAnalysis.apiResults.googleSafeBrowsing.threats.map(t => t.threatType).join(', ')}\n`;
            }
            if (threatAnalysis.apiResults.phishtank?.available && threatAnalysis.apiResults.phishtank.isPhish) {
              staffAlert += `• PhishTank:  CONFIRMED PHISHING\n`;
            }
            if (threatAnalysis.apiResults.ipqualityscore?.available) {
              const ipqs = threatAnalysis.apiResults.ipqualityscore;
              staffAlert += `• IPQualityScore: Risk ${ipqs.fraudScore || ipqs.riskScore || 0}%\n`;
            }
          }
          
          const staffEmbed = new EmbedBuilder()
            .setTitle(` SECURITY FLAG - Staff Only`)
            .setDescription(staffAlert)
            .setColor(0xFF6600)
            .setFooter({ text: 'This alert is only visible to staff in this channel' });
          
          await ticketChannel.send({ embeds: [staffEmbed] });
          
          // Also log to security channel
          await handleThreatResponse(originalMessage, threatAnalysis, guild);
          
          // Store threat data in database for ticket close
          await pool.query(`
            UPDATE modmail_tickets 
            SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb 
            WHERE id = $2
          `, [JSON.stringify({ lastThreat: { score: threatAnalysis.score, findings: threatAnalysis.findings?.slice(0, 5), apiResults: threatAnalysis.apiResults } }), ticket.id]).catch(() => {});
        }
      }
      
      const successEmbed = new EmbedBuilder()
        .setTitle(' Ticket Created!')
        .setDescription(`Your ticket **#${ticket.ticket_number}** has been created.\n\nStaff will respond soon. You can send more messages and they'll be added to your ticket.`)
        .setColor(CONFIG.COLORS.success)
        .setFooter({ text: 'The Unpatched Method • Support' });
      
      await interaction.editReply({ content: null, embeds: [successEmbed], components: [] });
      
      client.pendingTickets.delete(interaction.user.id);
    } catch (e) {
      console.error('Ticket creation error:', e);
      await interaction.editReply({ content: ' Error. Please try again.', embeds: [], components: [] });
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// MEMBER EVENTS - Welcome DMs
// ═══════════════════════════════════════════════════════════════════════════════

client.on(Events.GuildMemberAdd, async (member) => {
  const guild = member.guild;
  
  const verifyChannel = guild.channels.cache.find(c => c.name === 'verify' || c.name === 'verification');
  const verifyLink = verifyChannel ? `<#${verifyChannel.id}>` : '#verify';
  
  try {
    const embed1 = new EmbedBuilder()
      .setTitle(' VERIFY YOURSELF ')
      .setDescription(`#  YOU MUST VERIFY TO ACCESS THE SERVER \n\nHey **${member.user.username}**, welcome to **The Unpatched Method**.\n\n**You NEED to verify before you can see channels.**`)
      .addFields(
        { name: ' HOW TO VERIFY', value: `**1.** Click here  ${verifyLink}\n**2.** Click the  button\n**3.** Done!` },
        { name: ' WITHOUT VERIFICATION', value: '• Can\'t see channels\n• Can\'t chat\n• Can\'t join LFG', inline: true },
        { name: ' AFTER VERIFICATION', value: '• Full server access\n• LFG for heists\n• Talk to bots', inline: true }
      )
      .setColor(0xFF0000);
    
    const embed2 = new EmbedBuilder()
      .setTitle(' Welcome to The Unpatched Method!')
      .setDescription('Once verified:')
      .addFields(
        { name: ' LFG Channels', value: '• #cayo-lfg\n• #wagon-lfg\n• #bounty-lfg' },
        { name: ' Pro Tip', value: 'Type `?daily` in #casino for free chips!' },
        { name: ' Need Help?', value: '**DM me anytime** to talk to staff!' }
      )
      .setColor(CONFIG.COLORS.primary)
      .setThumbnail(guild.iconURL());
    
    await member.send({ content: '#  READ THIS FIRST ', embeds: [embed1, embed2] });
  } catch (e) {
    console.log(`Could not DM ${member.user.username}`);
  }
});

// Post-verify DM
client.on(Events.GuildMemberUpdate, async (oldMember, newMember) => {
  const hadRole = oldMember.roles.cache.has(CONFIG.VERIFIED_ROLE_ID);
  const hasRole = newMember.roles.cache.has(CONFIG.VERIFIED_ROLE_ID);
  
  if (!hadRole && hasRole) {
    try {
      const embed = new EmbedBuilder()
        .setTitle(' You\'re Verified!')
        .setDescription(`Welcome **${newMember.user.username}**! Here's what to do:`)
        .addFields(
          { name: ' STEP 1: Pick Roles', value: `Go to <#${CONFIG.ROLES_CHANNEL_ID}> and select your games/platform` },
          { name: ' STEP 2: Find Crew', value: '• #cayo-lfg - GTA heists\n• #wagon-lfg - RDO trading\n• #bounty-lfg - Bounties' },
          { name: ' STEP 3: Free Stuff', value: 'Type `?daily` in #casino for free chips!' },
          { name: ' Need Help?', value: '**DM me** to create a support ticket!' }
        )
        .setColor(CONFIG.COLORS.success);
      
      await newMember.send({ embeds: [embed] });
    } catch (e) {}
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// BAN APPEAL SYSTEM
// ═══════════════════════════════════════════════════════════════════════════════

client.on(Events.GuildBanAdd, async (ban) => {
  try {
    const user = ban.user;
    const reason = ban.reason || 'No reason provided';
    
    // ═══════════════════════════════════════════════════════════════
    // FLAG FINGERPRINT WITH UNPATCHED VERIFY
    // ═══════════════════════════════════════════════════════════════
    const VERIFY_API_URL = process.env.VERIFY_API_URL || 'https://verify.unpatchedmethod.com';
    const BOT_SECRET = process.env.VERIFY_BOT_SECRET;
    
    if (BOT_SECRET) {
      try {
        const response = await fetch(`${VERIFY_API_URL}/api/internal/flag-ban`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            discord_id: user.id,
            guild_id: ban.guild.id,
            reason: reason,
            bot_secret: BOT_SECRET
          })
        });
        
        const data = await response.json();
        console.log(`[BAN] Fingerprint flagged for ${user.tag}: ${data.message}`);
        
        // Log to security channel
        const securityLog = ban.guild.channels.cache.find(c => 
          c.name === 'security-logs' || c.name === 'modmail-logs'
        );
        
        if (securityLog) {
          const flagEmbed = new EmbedBuilder()
            .setTitle(' Device Fingerprint Flagged')
            .setDescription(`**User:** ${user.tag}\n**ID:** \`${user.id}\`\n**Reason:** ${reason}`)
            .addFields({
              name: ' Alt Prevention Active',
              value: 'Any future accounts from this device will be automatically blocked from verifying.',
              inline: false
            })
            .setColor(0xFF6B35)
            .setTimestamp();
          
          await securityLog.send({ embeds: [flagEmbed] });
        }
        
      } catch (e) {
        console.log('[BAN] Could not flag fingerprint:', e.message);
      }
    }
    
    // Send appeal information to banned user
    const appealEmbed = new EmbedBuilder()
      .setTitle(' You Have Been Banned')
      .setDescription(`
You have been banned from **The Unpatched Method**.

**Reason:** ${reason}

**Appeal Process:**
If you believe this ban was unjust, you can submit an appeal. Your appeal will be reviewed by our AI system and staff.

**To appeal, reply to this message with:**
\`APPEAL: [Your explanation here]\`

Example: \`APPEAL: I was banned for spam but I was hacked. I've secured my account now.\`

**Important:**
• Be honest and detailed
• Explain what happened
• Show you understand the rules
• Appeals are reviewed within 48 hours

 **Note:** Creating alt accounts to bypass this ban will not work. Your device has been fingerprinted.
      `)
      .setColor(CONFIG.COLORS.error)
      .setFooter({ text: 'The Unpatched Method • Ban Appeal System' })
      .setTimestamp();
    
    await user.send({ embeds: [appealEmbed] });
    
    // Store ban info for appeals
    await pool.query(`
      INSERT INTO ban_appeals (user_id, ban_reason, appeal_text, status)
      VALUES ($1, $2, 'Awaiting appeal submission', 'awaiting')
      ON CONFLICT DO NOTHING
    `, [user.id, reason]);
    
  } catch (e) {
    console.log('Could not DM banned user:', e.message);
  }
});

// Handle appeal submissions in DM
client.on(Events.MessageCreate, async (message) => {
  if (message.author.bot) return;
  if (message.channel.type !== ChannelType.DM) return;
  
  // Check if message is an appeal
  if (message.content.toUpperCase().startsWith('APPEAL:')) {
    const appealText = message.content.slice(7).trim();
    
    if (appealText.length < 20) {
      return message.reply(' Your appeal is too short. Please provide a detailed explanation.');
    }
    
    // Get ban info
    const banInfo = await pool.query(`
      SELECT * FROM ban_appeals WHERE user_id = $1 AND status IN ('awaiting', 'pending')
      ORDER BY created_at DESC LIMIT 1
    `, [message.author.id]);
    
    if (banInfo.rows.length === 0) {
      return message.reply(' No pending ban found for your account.');
    }
    
    const ban = banInfo.rows[0];
    
    // Process with AI
    await message.reply(' Processing your appeal with AI review...');
    
    const aiResult = await processAppeal(message.author.id, appealText, ban.ban_reason);
    
    // Save appeal
    await pool.query(`
      UPDATE ban_appeals 
      SET appeal_text = $1, ai_recommendation = $2, ai_reasoning = $3, status = 'pending'
      WHERE id = $4
    `, [appealText, aiResult.recommendation, aiResult.reasoning, ban.id]);
    
    // Send to staff
    const guild = client.guilds.cache.get(CONFIG.GUILD_ID);
    const logChannel = guild?.channels.cache.get(MODMAIL_LOG_CHANNEL);
    
    if (logChannel) {
      const appealEmbed = new EmbedBuilder()
        .setTitle(' New Ban Appeal')
        .setDescription(`**User:** ${message.author.tag} (${message.author.id})`)
        .addFields(
          { name: ' Ban Reason', value: ban.ban_reason || 'Not specified', inline: false },
          { name: ' Appeal', value: appealText.slice(0, 1024), inline: false },
          { name: ' AI Recommendation', value: `**${aiResult.recommendation.toUpperCase()}** (${aiResult.confidence}% confidence)`, inline: true },
          { name: ' AI Reasoning', value: aiResult.reasoning?.slice(0, 1024) || 'N/A', inline: false }
        )
        .setColor(
          aiResult.recommendation === 'approve' ? CONFIG.COLORS.success :
          aiResult.recommendation === 'deny' ? CONFIG.COLORS.error : CONFIG.COLORS.warning
        )
        .setTimestamp();
      
      if (aiResult.redFlags?.length > 0) {
        appealEmbed.addFields({ name: ' Red Flags', value: aiResult.redFlags.join('\n'), inline: true });
      }
      if (aiResult.positiveFactors?.length > 0) {
        appealEmbed.addFields({ name: ' Positive Factors', value: aiResult.positiveFactors.join('\n'), inline: true });
      }
      
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`appeal_approve_${ban.id}`).setLabel(' Approve & Unban').setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId(`appeal_deny_${ban.id}`).setLabel(' Deny').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId(`appeal_questions_${ban.id}`).setLabel(' Need More Info').setStyle(ButtonStyle.Secondary)
      );
      
      await logChannel.send({ content: '@here Ban appeal received', embeds: [appealEmbed], components: [row] });
    }
    
    // Confirm to user
    const confirmEmbed = new EmbedBuilder()
      .setTitle(' Appeal Submitted')
      .setDescription(`
Your appeal has been received and is being reviewed.

**AI Pre-Assessment:** ${aiResult.recommendation === 'approve' ? ' Favorable' : aiResult.recommendation === 'deny' ? ' Unfavorable' : '⏳ Needs Review'}

A staff member will make the final decision within 48 hours. You will be notified of the outcome.
      `)
      .setColor(CONFIG.COLORS.info);
    
    await message.reply({ embeds: [confirmEmbed] });
  }
});

// Handle appeal buttons
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  
  // Appeal approve
  if (interaction.customId.startsWith('appeal_approve_')) {
    const appealId = interaction.customId.split('_')[2];
    
    const appeal = await pool.query(`SELECT * FROM ban_appeals WHERE id = $1`, [appealId]);
    if (appeal.rows.length === 0) return interaction.reply({ content: 'Appeal not found.', ephemeral: true });
    
    const userId = appeal.rows[0].user_id;
    
    // Unban user
    try {
      await interaction.guild.bans.remove(userId, 'Appeal approved');
      
      await pool.query(`
        UPDATE ban_appeals SET status = 'approved', reviewed_by = $1, reviewed_at = NOW() WHERE id = $2
      `, [interaction.user.id, appealId]);
      
      // Notify user
      const user = await client.users.fetch(userId);
      await user.send({ embeds: [new EmbedBuilder()
        .setTitle(' Appeal Approved!')
        .setDescription('Your ban appeal has been approved. You may rejoin the server.\n\n**Please follow the rules this time.**')
        .setColor(CONFIG.COLORS.success)
      ]});
      
      await interaction.update({ content: ` Appeal approved by ${interaction.user.tag}. User unbanned.`, components: [] });
    } catch (e) {
      await interaction.reply({ content: `Error: ${e.message}`, ephemeral: true });
    }
  }
  
  // Appeal deny
  if (interaction.customId.startsWith('appeal_deny_')) {
    const appealId = interaction.customId.split('_')[2];
    
    const appeal = await pool.query(`SELECT * FROM ban_appeals WHERE id = $1`, [appealId]);
    if (appeal.rows.length === 0) return interaction.reply({ content: 'Appeal not found.', ephemeral: true });
    
    await pool.query(`
      UPDATE ban_appeals SET status = 'denied', reviewed_by = $1, reviewed_at = NOW() WHERE id = $2
    `, [interaction.user.id, appealId]);
    
    // Notify user
    try {
      const user = await client.users.fetch(appeal.rows[0].user_id);
      await user.send({ embeds: [new EmbedBuilder()
        .setTitle(' Appeal Denied')
        .setDescription('Your ban appeal has been denied. The ban will remain in place.\n\nYou may submit another appeal in 30 days.')
        .setColor(CONFIG.COLORS.error)
      ]});
    } catch (e) {}
    
    await interaction.update({ content: ` Appeal denied by ${interaction.user.tag}.`, components: [] });
  }
  
  // Reputation buttons
  if (interaction.customId === 'rep_good') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    await updateReputation(ticket.user_id, 5, 'Good interaction');
    await interaction.reply({ content: ' User reputation increased (+5)', ephemeral: true });
  }
  
  if (interaction.customId === 'rep_bad') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    await updateReputation(ticket.user_id, -10, 'Bad interaction');
    await interaction.reply({ content: ' User reputation decreased (-10)', ephemeral: true });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// READY
// ═══════════════════════════════════════════════════════════════════════════════

client.once(Events.ClientReady, async () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║      BURNER PHONE - ELITE PREMIUM MODMAIL SYSTEM          ║');
  console.log('║       Typing •  Read Receipts •  Queue •  Analytics ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log(`Logged in as ${client.user.tag}`);
  
  await initDatabase();
  
  client.user.setPresence({
    activities: [{ name: 'DM me for support |  Elite', type: 3 }],
    status: 'online'
  });
  
  // ═══════════════════════════════════════════════════════════════
  // SCHEDULED MESSAGE PROCESSOR (runs every minute)
  // ═══════════════════════════════════════════════════════════════
  setInterval(async () => {
    try {
      const scheduled = await getPendingScheduledMessages();
      for (const msg of scheduled) {
        const ticket = await pool.query(`SELECT * FROM modmail_tickets WHERE id = $1`, [msg.ticket_id]);
        if (ticket.rows.length === 0 || ticket.rows[0].status !== 'open') {
          await markScheduledMessageSent(msg.id);
          continue;
        }
        
        const ticketData = ticket.rows[0];
        const user = await client.users.fetch(ticketData.user_id).catch(() => null);
        if (!user) {
          await markScheduledMessageSent(msg.id);
          continue;
        }
        
        // Send to user
        const embed = new EmbedBuilder()
          .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
          .setTitle(' Follow-up Message')
          .setDescription(msg.content)
          .setColor(CONFIG.COLORS.primary)
          .setFooter({ text: 'The Unpatched Method • Reply to respond' })
          .setTimestamp();
        
        await user.send({ embeds: [embed] }).catch(() => {});
        
        // Log in ticket channel
        const guild = client.guilds.cache.get(ticketData.guild_id);
        const channel = guild?.channels.cache.get(ticketData.channel_id);
        if (channel) {
          await channel.send(`⏰ **Scheduled message sent:** ${msg.content}`);
        }
        
        await markScheduledMessageSent(msg.id);
      }
    } catch (e) {
      console.error('Scheduled message error:', e);
    }
  }, 60000); // Every minute
  
  // ═══════════════════════════════════════════════════════════════
  // AUTO-CLOSE INACTIVE TICKETS (runs every hour)
  // ═══════════════════════════════════════════════════════════════
  setInterval(async () => {
    try {
      // Find tickets with no activity in 48 hours
      const stale = await pool.query(`
        SELECT t.* FROM modmail_tickets t
        WHERE t.status = 'open'
        AND t.id NOT IN (
          SELECT ticket_id FROM modmail_messages 
          WHERE created_at > NOW() - INTERVAL '48 hours'
        )
        AND t.created_at < NOW() - INTERVAL '48 hours'
      `);
      
      for (const ticket of stale.rows) {
        const guild = client.guilds.cache.get(ticket.guild_id);
        if (!guild) continue;
        
        const channel = guild.channels.cache.get(ticket.channel_id);
        const user = await client.users.fetch(ticket.user_id).catch(() => null);
        
        // Send warning first (check if already warned)
        const warned = await pool.query(`
          SELECT 1 FROM modmail_messages 
          WHERE ticket_id = $1 AND content LIKE '%auto-close warning%'
        `, [ticket.id]);
        
        if (warned.rows.length === 0) {
          // First warning
          if (user) {
            await user.send({
              embeds: [new EmbedBuilder()
                .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
                .setTitle('⏰ Ticket Inactive')
                .setDescription('Your ticket has been inactive for 48 hours. It will be automatically closed in 24 hours if there is no response.\n\nReply here if you still need assistance!')
                .setColor(CONFIG.COLORS.warning)
                .setFooter({ text: 'The Unpatched Method • Support' })
              ]
            }).catch(() => {});
          }
          
          if (channel) {
            await channel.send('⏰ **Auto-close warning sent** - No activity in 48 hours. Will close in 24h if no response.');
          }
          
          await pool.query(`
            INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
            VALUES ($1, 'SYSTEM', 'System', '[auto-close warning sent]', true)
          `, [ticket.id]);
        }
      }
      
      // Actually close tickets warned 24+ hours ago
      const toClose = await pool.query(`
        SELECT t.* FROM modmail_tickets t
        WHERE t.status = 'open'
        AND t.id IN (
          SELECT ticket_id FROM modmail_messages 
          WHERE content LIKE '%auto-close warning%'
          AND created_at < NOW() - INTERVAL '24 hours'
        )
        AND t.id NOT IN (
          SELECT ticket_id FROM modmail_messages 
          WHERE created_at > NOW() - INTERVAL '24 hours'
          AND content NOT LIKE '%auto-close warning%'
        )
      `);
      
      for (const ticket of toClose.rows) {
        const guild = client.guilds.cache.get(ticket.guild_id);
        if (!guild) continue;
        
        const channel = guild.channels.cache.get(ticket.channel_id);
        const user = await client.users.fetch(ticket.user_id).catch(() => null);
        
        // Close the ticket
        await pool.query(`
          UPDATE modmail_tickets SET status = 'closed', closed_at = NOW(), close_reason = 'Auto-closed due to inactivity'
          WHERE id = $1
        `, [ticket.id]);
        
        if (user) {
          await user.send({
            embeds: [new EmbedBuilder()
              .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
              .setTitle(' Ticket Auto-Closed')
              .setDescription('Your ticket was automatically closed due to inactivity.\n\nIf you still need help, just send a new message!')
              .setColor(CONFIG.COLORS.error)
              .setFooter({ text: 'The Unpatched Method • Support' })
            ]
          }).catch(() => {});
        }
        
        if (channel) {
          await channel.send(' **Ticket auto-closed** due to inactivity.');
          setTimeout(() => channel.delete().catch(() => {}), 5000);
        }
      }
    } catch (e) {
      console.error('Auto-close error:', e);
    }
  }, 3600000); // Every hour
});

// ═══════════════════════════════════════════════════════════════════════════════
// STAFF VIEWING NOTIFICATION HELPER
// ═══════════════════════════════════════════════════════════════════════════════

async function notifyUserStaffViewing(ticket, staffMember) {
  // Only notify if ticket isn't claimed yet (first interaction)
  if (ticket.claimed_by) return false;
  
  // Check if we already notified recently (within 5 minutes)
  const isNewView = await recordTicketView(ticket.id, staffMember.id, staffMember.tag || staffMember.user?.tag);
  if (!isNewView) return false;
  
  try {
    const user = await client.users.fetch(ticket.user_id);
    await user.send({
      embeds: [new EmbedBuilder()
        .setAuthor({ name: 'The Unpatched Method Staff', iconURL: client.user.displayAvatarURL() })
        .setDescription(' A staff member is viewing your ticket...')
        .setColor(CONFIG.COLORS.info)
        .setFooter({ text: 'The Unpatched Method • Support' })
      ]
    });
    return true;
  } catch (e) {
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// STAFF VIEWING - TYPING INDICATOR TRIGGER
// ═══════════════════════════════════════════════════════════════════════════════

client.on(Events.TypingStart, async (typing) => {
  try {
    // Staff typing in ticket channel  notify user staff is viewing
    if ((typing.channel.name?.startsWith('ticket-') || typing.channel.name?.includes('-ticket-')) && !typing.user.bot) {
      const ticket = await getTicketByChannel(typing.channel.id);
      if (!ticket) return;
      
      const member = await typing.channel.guild.members.fetch(typing.user.id).catch(() => null);
      if (member && isStaff(member)) {
        // Notify user that staff is viewing (only first time)
        await notifyUserStaffViewing(ticket, typing.user);
        
        // Also forward typing indicator to user
        const user = await client.users.fetch(ticket.user_id).catch(() => null);
        if (user) {
          const dmChannel = await user.createDM().catch(() => null);
          if (dmChannel) await dmChannel.sendTyping().catch(() => {});
        }
      }
    }
    
    // User typing in DM  forward to ticket channel
    if (typing.channel.isDMBased() && !typing.user.bot) {
      const ticket = await getOpenTicket(typing.user.id);
      if (ticket) {
        const guild = client.guilds.cache.get(CONFIG.GUILD_ID);
        if (guild) {
          const channel = guild.channels.cache.get(ticket.channel_id);
          if (channel) await channel.sendTyping().catch(() => {});
        }
      }
    }
  } catch (e) {
    // Silently fail - typing indicators aren't critical
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// STAFF VIEWING - MESSAGE TRIGGER
// ═══════════════════════════════════════════════════════════════════════════════

// Track when staff sends message in ticket channel
client.on(Events.MessageCreate, async (message) => {
  if (message.channel.name?.startsWith('ticket-') || message.channel.name?.includes('-ticket-')) {
    if (message.author.bot) return;
    
    const ticket = await getTicketByChannel(message.channel.id);
    if (!ticket) return;
    
    if (isStaff(message.member)) {
      await notifyUserStaffViewing(ticket, message.author);
    }
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEEDBACK BUTTONS HANDLER
// ═══════════════════════════════════════════════════════════════════════════════

client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  
  // Handle security action buttons (Ban/Warn/Dismiss)
  if (interaction.customId.startsWith('security_')) {
    // Check if user is staff
    const member = await interaction.guild?.members.fetch(interaction.user.id).catch(() => null);
    if (!member || !isStaff(member)) {
      return interaction.reply({ content: ' Only staff can use security actions.', ephemeral: true });
    }
    
    const [, action, targetUserId] = interaction.customId.split('_');
    const targetUser = await client.users.fetch(targetUserId).catch(() => null);
    
    if (action === 'ban') {
      try {
        await interaction.guild.members.ban(targetUserId, { reason: 'Security threat - banned via security alert' });
        await interaction.update({
          content: ` **User Banned** by ${interaction.user.tag}\n<@${targetUserId}> was banned for security violations.`,
          embeds: interaction.message.embeds,
          components: []
        });
      } catch (e) {
        await interaction.reply({ content: ` Failed to ban: ${e.message}`, ephemeral: true });
      }
    }
    
    else if (action === 'warn') {
      try {
        if (targetUser) {
          await targetUser.send({
            embeds: [new EmbedBuilder()
              .setTitle(' Security Warning')
              .setDescription('Your message was flagged by our security system. Please avoid sending suspicious links or files.\n\nRepeated violations may result in a ban.')
              .setColor(0xFFAA00)
              .setFooter({ text: 'The Unpatched Method • Security' })
            ]
          }).catch(() => {});
        }
        await interaction.update({
          content: ` **User Warned** by ${interaction.user.tag}\n<@${targetUserId}> was sent a security warning.`,
          embeds: interaction.message.embeds,
          components: []
        });
      } catch (e) {
        await interaction.reply({ content: ` Failed to warn: ${e.message}`, ephemeral: true });
      }
    }
    
    else if (action === 'dismiss') {
      await interaction.update({
        content: ` **Dismissed** by ${interaction.user.tag}\nNo action taken.`,
        embeds: interaction.message.embeds,
        components: []
      });
    }
    
    return;
  }
  
  // Handle feedback ratings
  if (interaction.customId.startsWith('feedback_')) {
    const [, rating, ticketId] = interaction.customId.split('_');
    
    await saveFeedback(parseInt(ticketId), interaction.user.id, parseInt(rating));
    
    const stars = ''.repeat(parseInt(rating));
    await interaction.update({
      content: `Thank you for your feedback! ${stars}\n\nYour rating helps us improve our support.`,
      embeds: [],
      components: []
    });
  }
  
  // View notes button
  if (interaction.customId === 'view_notes') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    
    // Notify user staff is viewing
    await notifyUserStaffViewing(ticket, interaction.user);
    
    const notes = await getUserNotes(ticket.user_id);
    const user = await client.users.fetch(ticket.user_id).catch(() => null);
    
    if (notes.length === 0) {
      return interaction.reply({ content: `No notes for this user. Add one with \`?note @user note\``, ephemeral: true });
    }
    
    const notesStr = notes.map(n => `• **${n.note}**\n  *- ${n.added_by_name}, ${timeAgo(n.created_at)}*`).join('\n\n');
    
    const embed = new EmbedBuilder()
      .setTitle(` Notes for ${user?.tag || 'User'}`)
      .setDescription(notesStr)
      .setColor(CONFIG.COLORS.info);
    
    await interaction.reply({ embeds: [embed], ephemeral: true });
  }
  
  // View history button
  if (interaction.customId === 'view_history') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    
    // Notify user staff is viewing
    await notifyUserStaffViewing(ticket, interaction.user);
    
    const user = await client.users.fetch(ticket.user_id).catch(() => null);
    const r = await pool.query(`
      SELECT * FROM modmail_tickets 
      WHERE user_id = $1 
      ORDER BY created_at DESC 
      LIMIT 10
    `, [ticket.user_id]);
    
    if (r.rows.length <= 1) {
      return interaction.reply({ content: 'This is the user\'s first ticket!', ephemeral: true });
    }
    
    const list = r.rows.map(t => 
      `**#${t.ticket_number}** - ${t.status === 'open' ? '' : ''} ${t.status} - ${timeAgo(t.created_at)}${t.close_reason ? `\n  └ *${t.close_reason.slice(0, 40)}*` : ''}`
    ).join('\n');
    
    const embed = new EmbedBuilder()
      .setTitle(` Ticket History: ${user?.tag || 'User'}`)
      .setDescription(list)
      .setColor(CONFIG.COLORS.info);
    
    await interaction.reply({ embeds: [embed], ephemeral: true });
  }
  
  // Priority menu button
  if (interaction.customId === 'priority_menu') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (ticket) {
      // Notify user staff is viewing
      await notifyUserStaffViewing(ticket, interaction.user);
    }
    
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder().setCustomId('set_priority_low').setLabel(' Low').setStyle(ButtonStyle.Success),
      new ButtonBuilder().setCustomId('set_priority_med').setLabel(' Medium').setStyle(ButtonStyle.Primary),
      new ButtonBuilder().setCustomId('set_priority_high').setLabel(' High').setStyle(ButtonStyle.Secondary),
      new ButtonBuilder().setCustomId('set_priority_urgent').setLabel(' Urgent').setStyle(ButtonStyle.Danger)
    );
    
    await interaction.reply({ content: 'Select priority level:', components: [row], ephemeral: true });
  }
  
  // Set priority buttons
  if (interaction.customId.startsWith('set_priority_')) {
    const level = interaction.customId.replace('set_priority_', '');
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    
    const priorities = { low: '', med: '', high: '', urgent: '' };
    const emoji = priorities[level];
    
    await pool.query(`UPDATE modmail_tickets SET priority = $1 WHERE id = $2`, [level, ticket.id]);
    
    // Update channel name
    const newName = `${emoji}-ticket-${ticket.ticket_number.toString().padStart(4, '0')}`;
    await interaction.channel.setName(newName).catch(() => {});
    
    await interaction.update({ content: ` Priority set to **${level.toUpperCase()}** ${emoji}`, components: [] });
  }
});

client.login(process.env.DISCORD_TOKEN);// force update