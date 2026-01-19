/**
 * ██████╗ ██╗   ██╗██████╗ ███╗   ██╗███████╗██████╗     ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗
 * ██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔══██╗    ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝
 * ██████╔╝██║   ██║██████╔╝██╔██╗ ██║█████╗  ██████╔╝    ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗  
 * ██╔══██╗██║   ██║██╔══██╗██║╚██╗██║██╔══╝  ██╔══██╗    ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝  
 * ██████╔╝╚██████╔╝██║  ██║██║ ╚████║███████╗██║  ██║    ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗
 * ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 * 
 * BURNER PHONE - ULTIMATE Modmail & Security System
 * Advanced AI, Link Scanning, Translation, Threat Detection
 */

require('dotenv').config();
const { 
  Client, GatewayIntentBits, Partials, EmbedBuilder, 
  PermissionFlagsBits, Events, ActionRowBuilder, ButtonBuilder, 
  ButtonStyle, ChannelType, StringSelectMenuBuilder
} = require('discord.js');
const { Pool } = require('pg');
const Anthropic = require('@anthropic-ai/sdk');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages,
    GatewayIntentBits.GuildBans
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
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

const CONFIG = {
  PREFIX: '?',
  GUILD_ID: '1446317951757062256',
  VERIFIED_ROLE_ID: '1453304594317836423',
  ROLES_CHANNEL_ID: '1453304724681134163',
  COLORS: { primary: 0xFF6B35, success: 0x00FF00, error: 0xFF0000, warning: 0xFFAA00, info: 0x0099FF, danger: 0xFF0000 }
};

// Known scam patterns
const SCAM_PATTERNS = [
  /free\s*nitro/i,
  /discord\s*nitro\s*gift/i,
  /steam\s*gift/i,
  /click\s*here\s*to\s*claim/i,
  /you\s*have\s*been\s*selected/i,
  /won\s*a?\s*prize/i,
  /verify\s*your\s*account\s*at/i,
  /suspicious\s*activity/i,
  /account\s*will\s*be\s*terminated/i,
  /login\s*to\s*verify/i,
  /bit\.ly/i,
  /discord\.gift/i,
  /discordgift/i,
  /steamcommunity\.ru/i,
  /dlscord/i,
  /disc0rd/i,
  /discorcl/i
];

// Suspicious domains
const SUSPICIOUS_DOMAINS = [
  'bit.ly', 'tinyurl.com', 'shorturl.at', 'rb.gy',
  'dlscord.com', 'discorcl.com', 'disc0rd.com',
  'steamcommunlty.com', 'steampowered.ru'
];

// ═══════════════════════════════════════════════════════════════════════════════
// LINK SCANNER & SECURITY
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

async function scanWithVirusTotal(url) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { malicious: 0, suspicious: 0 };
  
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
    
    const submitData = await submitResponse.json();
    const analysisId = submitData.data?.id;
    
    if (!analysisId) return { malicious: 0, suspicious: 0 };
    
    // Wait a moment then get results
    await new Promise(r => setTimeout(r, 3000));
    
    const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { 'x-apikey': apiKey }
    });
    
    const resultData = await resultResponse.json();
    const stats = resultData.data?.attributes?.stats || {};
    
    return {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0
    };
  } catch (e) {
    console.log('VirusTotal error:', e.message);
    return { malicious: 0, suspicious: 0 };
  }
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
  if (!anthropic) return { mood: 'neutral', urgency: 'normal', emoji: '😐' };
  
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
    return { mood: 'neutral', urgency: 'normal', emoji: '😐', escalate: false };
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
    CREATE TABLE modmail_tickets (
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
      created_at TIMESTAMP DEFAULT NOW(),
      closed_at TIMESTAMP,
      closed_by TEXT,
      close_reason TEXT
    )
  `);
  await pool.query(`
    CREATE TABLE modmail_messages (
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
    CREATE TABLE modmail_blacklist (
      user_id TEXT PRIMARY KEY,
      reason TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE TABLE modmail_canned (
      name TEXT PRIMARY KEY,
      content TEXT NOT NULL
    )
  `);
  
  // User reputation system
  await pool.query(`
    CREATE TABLE user_reputation (
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
    CREATE TABLE ban_appeals (
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
    CREATE TABLE link_scans (
      id SERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      user_id TEXT NOT NULL,
      is_safe BOOLEAN,
      threats TEXT[],
      scanned_at TIMESTAMP DEFAULT NOW()
    )
  `);
  
  console.log('[DB] All tables ready');
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

const MODMAIL_LOG_CHANNEL = '1462325739297968279';

async function logToModmail(guild, ticket, closedBy, reason, kicked = false) {
  try {
    const logChannel = guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
    if (!logChannel) return;
    
    const user = await client.users.fetch(ticket.user_id).catch(() => null);
    
    const embed = new EmbedBuilder()
      .setTitle(`🔒 Ticket #${ticket.ticket_number} Closed${kicked ? ' & Kicked' : ''}`)
      .addFields(
        { name: '👤 User', value: user ? `${user.tag} (${user.id})` : ticket.user_id, inline: true },
        { name: '👮 Closed By', value: closedBy.tag, inline: true },
        { name: '📅 Opened', value: `<t:${Math.floor(new Date(ticket.created_at).getTime() / 1000)}:R>`, inline: true },
        { name: '📝 Reason', value: reason || 'No reason provided', inline: false }
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
// TICKET CREATION (Enhanced with AI/Security)
// ═══════════════════════════════════════════════════════════════════════════════

async function createTicket(user, guild, message, extraData = {}) {
  const ticketNum = await getNextTicketNumber();
  const { translation, mood, reputation, linkResults, scamThreats } = extraData;
  
  // Find or create category
  let category = guild.channels.cache.find(c => c.name === '📨 MODMAIL' && c.type === ChannelType.GuildCategory);
  if (!category) {
    category = await guild.channels.create({
      name: '📨 MODMAIL',
      type: ChannelType.GuildCategory,
      permissionOverwrites: [{ id: guild.id, deny: [PermissionFlagsBits.ViewChannel] }]
    });
  }
  
  // Create channel
  const channel = await guild.channels.create({
    name: `ticket-${ticketNum.toString().padStart(4, '0')}`,
    type: ChannelType.GuildText,
    parent: category.id,
    topic: `User: ${user.tag} (${user.id}) | ${mood?.emoji || '😐'} ${mood?.mood || 'neutral'}`
  });
  
  // Save to DB with language
  const r = await pool.query(`
    INSERT INTO modmail_tickets (ticket_number, user_id, guild_id, channel_id, mood, language)
    VALUES ($1, $2, $3, $4, $5, $6) RETURNING *
  `, [ticketNum, user.id, guild.id, channel.id, mood?.mood || 'neutral', translation?.languageCode || 'en']);
  const ticket = r.rows[0];
  
  // Update user reputation - opened ticket
  await pool.query(`
    UPDATE user_reputation SET total_tickets = total_tickets + 1, last_updated = NOW() WHERE user_id = $1
  `, [user.id]);
  
  await pool.query(`
    INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, original_content, detected_language, is_staff)
    VALUES ($1, $2, $3, $4, $5, $6, false)
  `, [ticket.id, user.id, user.tag, translation?.translated || message, message, translation?.languageCode || 'en']);
  
  // Build comprehensive ticket embed
  const embed = new EmbedBuilder()
    .setTitle(`📨 Ticket #${ticketNum}`)
    .setDescription(`**User:** ${user} (${user.tag})\n**ID:** ${user.id}`)
    .setColor(CONFIG.COLORS.primary)
    .setThumbnail(user.displayAvatarURL())
    .setTimestamp();
  
  // Message content
  embed.addFields({ name: '📝 Message', value: message.slice(0, 1024) || 'No message', inline: false });
  
  // Translation if not English
  if (translation?.translated && !translation.isEnglish) {
    embed.addFields({ 
      name: `🌐 Translated from ${translation.language}`, 
      value: translation.translated.slice(0, 1024),
      inline: false 
    });
  }
  
  // Mood and urgency
  if (mood) {
    embed.addFields({ 
      name: '🎭 Mood Analysis', 
      value: `${mood.emoji} **${mood.mood}** | Urgency: **${mood.urgency}**`, 
      inline: true 
    });
  }
  
  // User reputation
  if (reputation) {
    const repEmoji = reputation.tier === 'trusted' ? '⭐' : 
                     reputation.tier === 'neutral' ? '😐' : 
                     reputation.tier === 'caution' ? '⚠️' : '🚨';
    embed.addFields({ 
      name: '📊 Reputation', 
      value: `${repEmoji} **${reputation.tier.toUpperCase()}** (Score: ${reputation.score}/100)\n${reputation.total_tickets} previous tickets`, 
      inline: true 
    });
  }
  
  // Link scan results
  if (linkResults && linkResults.length > 0) {
    const linkStatus = linkResults.map(r => 
      `${r.safe ? '✅' : '🚨'} ${r.url.slice(0, 40)}${r.url.length > 40 ? '...' : ''}`
    ).join('\n');
    embed.addFields({ name: '🔗 Links Scanned', value: linkStatus.slice(0, 1024), inline: false });
    
    const unsafeLinks = linkResults.filter(r => !r.safe);
    if (unsafeLinks.length > 0) {
      const threatDetails = unsafeLinks.flatMap(r => r.threats).join('\n• ');
      embed.addFields({ name: '⚠️ LINK THREATS DETECTED', value: `• ${threatDetails}`, inline: false });
      embed.setColor(CONFIG.COLORS.danger);
    }
  }
  
  // Scam pattern warnings
  if (scamThreats && scamThreats.length > 0) {
    embed.addFields({ name: '🚨 SCAM PATTERNS DETECTED', value: scamThreats.join('\n').slice(0, 1024), inline: false });
    embed.setColor(CONFIG.COLORS.danger);
  }
  
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('claim').setLabel('Claim').setStyle(ButtonStyle.Primary).setEmoji('✋'),
    new ButtonBuilder().setCustomId('close').setLabel('Close').setStyle(ButtonStyle.Danger).setEmoji('🔒'),
    new ButtonBuilder().setCustomId('priority').setLabel('Priority').setStyle(ButtonStyle.Secondary).setEmoji('⚡'),
    new ButtonBuilder().setCustomId('rep_good').setLabel('+Rep').setStyle(ButtonStyle.Success).setEmoji('👍'),
    new ButtonBuilder().setCustomId('rep_bad').setLabel('-Rep').setStyle(ButtonStyle.Danger).setEmoji('👎')
  );
  
  // Ping message with escalation if needed
  let pingContent = '@here New ticket!';
  if (mood?.escalate) {
    pingContent = `🚨 **AUTO-ESCALATION** 🚨 @here\n**Reason:** ${mood.reason}`;
  }
  if (reputation?.tier === 'problematic') {
    pingContent = `⚠️ **PROBLEM USER ALERT** ⚠️ @here\nThis user has a history of issues.`;
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
      return message.reply('🚫 You are blocked from support.');
    }
    
    const guild = client.guilds.cache.get(CONFIG.GUILD_ID);
    if (!guild) return;
    
    // ═══════════════════════════════════════════════════════════════
    // SECURITY SCANNING
    // ═══════════════════════════════════════════════════════════════
    
    // Check for threats
    const threats = detectThreats(message.content);
    if (threats.length > 0) {
      const criticalThreats = threats.filter(t => t.severity === 'critical');
      if (criticalThreats.length > 0) {
        // Log and alert staff
        const logChannel = guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
        if (logChannel) {
          const alertEmbed = new EmbedBuilder()
            .setTitle('🚨 CRITICAL THREAT DETECTED')
            .setDescription(`**User:** ${message.author.tag} (${message.author.id})\n**Message:** ${message.content.slice(0, 500)}`)
            .addFields({ name: 'Threats', value: criticalThreats.map(t => `• ${t.type}: ${t.severity}`).join('\n') })
            .setColor(CONFIG.COLORS.danger)
            .setTimestamp();
          await logChannel.send({ content: '@here', embeds: [alertEmbed] });
        }
        return message.reply('⚠️ Your message contains content that violates our policies. This has been reported to staff.');
      }
    }
    
    // Check for scam patterns
    const scamThreats = detectScamPatterns(message.content);
    
    // Scan links
    const links = extractLinks(message.content);
    const linkResults = [];
    for (const link of links) {
      const result = await scanLink(link);
      linkResults.push({ url: link, ...result });
      
      // Log scan
      await pool.query(`
        INSERT INTO link_scans (url, user_id, is_safe, threats)
        VALUES ($1, $2, $3, $4)
      `, [link, message.author.id, result.safe, result.threats]);
    }
    
    const unsafeLinks = linkResults.filter(r => !r.safe);
    
    // ═══════════════════════════════════════════════════════════════
    // TRANSLATION
    // ═══════════════════════════════════════════════════════════════
    
    const translation = await detectAndTranslate(message.content);
    
    // ═══════════════════════════════════════════════════════════════
    // MOOD DETECTION
    // ═══════════════════════════════════════════════════════════════
    
    const mood = await analyzeMood(message.content);
    
    // ═══════════════════════════════════════════════════════════════
    // GET USER REPUTATION
    // ═══════════════════════════════════════════════════════════════
    
    const reputation = await getUserReputation(message.author.id);
    
    let ticket = await getOpenTicket(message.author.id);
    
    // ALWAYS show warning and require confirmation for EVERY message
    const warningEmbed = new EmbedBuilder()
      .setTitle('⚠️ BEFORE YOU CONTINUE')
      .setDescription(`
**This is The Unpatched Method support system.**

This is for **legitimate inquiries only**:
• Server questions
• Reporting issues
• Appeals

**DO NOT use this for:**
❌ Trolling or spam
❌ Irrelevant messages
❌ Wasting staff time

**Misuse will result in a permanent ban.**
      `)
      .addFields({
        name: '📝 Your Message',
        value: message.content.slice(0, 500) || 'No message',
        inline: false
      })
      .setColor(CONFIG.COLORS.warning)
      .setFooter({ text: 'Click the button below to confirm and send your message' });
    
    const row = new ActionRowBuilder().addComponents(
      new ButtonBuilder()
        .setCustomId('confirm_ticket')
        .setLabel('✅ I Understand - Send My Message')
        .setStyle(ButtonStyle.Success),
      new ButtonBuilder()
        .setCustomId('cancel_ticket')
        .setLabel('❌ Cancel')
        .setStyle(ButtonStyle.Danger)
    );
    
    await message.reply({ embeds: [warningEmbed], components: [row] });
    
    // Store pending message with all scanned data
    client.pendingTickets = client.pendingTickets || new Map();
    client.pendingTickets.set(message.author.id, {
      content: message.content,
      guild: guild,
      user: message.author,
      translation: translation,
      mood: mood,
      reputation: reputation,
      linkResults: linkResults,
      scamThreats: scamThreats,
      existingTicket: ticket // Pass existing ticket if any
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
      const embed = new EmbedBuilder()
        .setTitle('📬 Message from The Unpatched Method Team')
        .setDescription(translatedContent)
        .setColor(CONFIG.COLORS.primary)
        .setFooter({ text: `Ticket #${ticket.ticket_number}` })
        .setTimestamp();
      
      await user.send({ embeds: [embed] });
      await message.react('📨');
    } catch (e) {
      await message.reply('⚠️ Could not DM user.');
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
        .setTitle('📝 Message Preview')
        .setDescription(`**To:** ${user.tag}\n\n**Message:**\n${content}`)
        .setColor(CONFIG.COLORS.warning)
        .setFooter({ text: 'Check for spelling errors before sending!' });
      
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`confirm_dm_${user.id}`).setLabel('✅ Send').setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId('cancel_dm').setLabel('❌ Cancel').setStyle(ButtonStyle.Danger)
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
      
      await message.channel.send('🔒 Closing ticket...');
      
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
      
      try {
        const user = await client.users.fetch(ticket.user_id);
        
        await user.send({ embeds: [new EmbedBuilder().setTitle('🔒 Ticket Closed').setDescription(`Reason: ${reason}\n\n*This conversation will be deleted shortly.*`).setColor(CONFIG.COLORS.error)] });
        
        await message.channel.send('🔥 Burning messages...');
        
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
      const logChannel = message.guild.channels.cache.get(MODMAIL_LOG_CHANNEL);
      if (logChannel) {
        const logEmbed = new EmbedBuilder()
          .setTitle(`🔒 Ticket #${ticket.ticket_number} Closed`)
          .addFields(
            { name: '👤 User', value: `<@${ticket.user_id}>`, inline: true },
            { name: '👮 Closed By', value: message.author.tag, inline: true },
            { name: '📝 Reason', value: reason, inline: true }
          )
          .setColor(CONFIG.COLORS.warning)
          .setTimestamp();
        
        const transcriptBuffer = Buffer.from(transcript, 'utf-8');
        await logChannel.send({ 
          embeds: [logEmbed], 
          files: [{ attachment: transcriptBuffer, name: `ticket-${ticket.ticket_number}-transcript.txt` }] 
        });
      }
      
      await message.channel.send('✅ Transcript saved. Deleting channel in 5 seconds...');
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
        await user.send({ embeds: [new EmbedBuilder().setTitle('🔒 Ticket Closed').setDescription(`Reason: ${reason}\n\n*This conversation will be deleted shortly.*`).setColor(CONFIG.COLORS.error)] });
        
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
          await message.channel.send(`👢 ${user.tag} has been kicked.`);
        }
      } catch (e) {
        console.log('Close and kick error:', e.message);
      }
      
      // Log to modmail-logs
      await logToModmail(message.guild, ticket, message.author, reason, true);
      
      await message.channel.send('🔒 Closing in 5 seconds... Messages burned 🔥');
      setTimeout(() => message.channel.delete().catch(() => {}), 5000);
    }
    
    // ?claim
    if (cmd === 'claim' && isStaff(message.member)) {
      const ticket = await getTicketByChannel(message.channel.id);
      if (!ticket) return;
      await pool.query(`UPDATE modmail_tickets SET claimed_by = $1 WHERE id = $2`, [message.author.id, ticket.id]);
      await message.reply(`✋ Claimed by ${message.author}`);
    }
    
    // ?tickets
    if (cmd === 'tickets' && isStaff(message.member)) {
      const r = await pool.query(`SELECT * FROM modmail_tickets WHERE guild_id = $1 AND status = 'open'`, [message.guild.id]);
      if (r.rows.length === 0) return message.reply('✨ No open tickets!');
      
      const list = r.rows.map(t => `#${t.ticket_number} - <@${t.user_id}> - <#${t.channel_id}>`).join('\n');
      await message.reply({ embeds: [new EmbedBuilder().setTitle('📨 Open Tickets').setDescription(list).setColor(CONFIG.COLORS.info)] });
    }
    
    // ?blacklist @user
    if (cmd === 'blacklist' && message.member.permissions.has(PermissionFlagsBits.Administrator)) {
      const user = message.mentions.users.first();
      if (!user) return message.reply('Usage: `?blacklist @user`');
      await pool.query(`INSERT INTO modmail_blacklist (user_id, reason) VALUES ($1, $2) ON CONFLICT DO NOTHING`, [user.id, args.slice(1).join(' ')]);
      await message.reply(`🚫 ${user.tag} blacklisted.`);
    }
    
    // ?unblacklist @user
    if (cmd === 'unblacklist' && message.member.permissions.has(PermissionFlagsBits.Administrator)) {
      const user = message.mentions.users.first();
      if (!user) return message.reply('Usage: `?unblacklist @user`');
      await pool.query(`DELETE FROM modmail_blacklist WHERE user_id = $1`, [user.id]);
      await message.reply(`✅ ${user.tag} unblacklisted.`);
    }
    
    // ?setupmodmail
    if (cmd === 'setupmodmail' && message.member.permissions.has(PermissionFlagsBits.Administrator)) {
      let cat = message.guild.channels.cache.find(c => c.name === '📨 MODMAIL');
      if (!cat) {
        cat = await message.guild.channels.create({
          name: '📨 MODMAIL',
          type: ChannelType.GuildCategory,
          permissionOverwrites: [{ id: message.guild.id, deny: [PermissionFlagsBits.ViewChannel] }]
        });
      }
      
      let log = message.guild.channels.cache.find(c => c.name === 'modmail-logs');
      if (!log) {
        log = await message.guild.channels.create({
          name: 'modmail-logs',
          type: ChannelType.GuildText,
          parent: cat.id
        });
      }
      
      let staffDm = message.guild.channels.cache.find(c => c.name === 'staff-dm');
      if (!staffDm) {
        staffDm = await message.guild.channels.create({
          name: 'staff-dm',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'Use ?dm @user message to contact members through the bot'
        });
        
        // Send instructions
        const instructionEmbed = new EmbedBuilder()
          .setTitle('📬 Staff DM Channel')
          .setDescription('Use this channel to DM server members through the bot.\n\n**Command:**\n`?dm @user Your message here`\n\n**What happens:**\n• User receives a DM from Burner Phone\n• A ticket is created to track the conversation\n• User can reply and it comes here')
          .setColor(CONFIG.COLORS.primary);
        await staffDm.send({ embeds: [instructionEmbed] });
      }
      
      // Create guide channel
      let guide = message.guild.channels.cache.find(c => c.name === 'modmail-guide');
      if (!guide) {
        guide = await message.guild.channels.create({
          name: 'modmail-guide',
          type: ChannelType.GuildText,
          parent: cat.id,
          topic: 'How to use the Burner Phone ULTIMATE modmail system'
        });
        
        // Send the guide
        const guideEmbed1 = new EmbedBuilder()
          .setTitle('📱 BURNER PHONE ULTIMATE - STAFF GUIDE')
          .setDescription(`This is your **secure modmail system** with advanced AI features.

**Features:**
🔒 Anonymous staff-to-member communication
🔗 Automatic link scanning & scam detection
🌐 Auto-translation for non-English users
🎭 AI mood detection & auto-escalation
📊 User reputation tracking
⚖️ AI-powered ban appeal system
🔥 Self-destructing messages`)
          .setColor(CONFIG.COLORS.primary);
        
        const guideEmbed2 = new EmbedBuilder()
          .setTitle('📥 WHEN A USER DMS THE BOT')
          .setDescription(`
**What happens:**
1. User must confirm they understand the rules first
2. Their message is scanned for:
   • 🔗 Dangerous links (VirusTotal scan)
   • 🚨 Scam patterns (fake nitro, phishing)
   • ⚠️ Threats (auto-reported)
3. AI detects their mood & language
4. Ticket created with all this intel
5. Just type to reply - they get anonymous DM

**They never see your name!**
          `)
          .setColor(CONFIG.COLORS.info);
        
        const guideEmbed3 = new EmbedBuilder()
          .setTitle('🔗 LINK SCANNING')
          .setDescription(`
**Every link is automatically scanned:**
✅ Safe links show green checkmark
🚨 Dangerous links show red alert

**Scans include:**
• Known phishing domains
• Fake Discord/Steam sites
• URL shorteners (flagged as suspicious)
• VirusTotal database check

**DO NOT click suspicious links!**
          `)
          .setColor(CONFIG.COLORS.warning);
        
        const guideEmbed4 = new EmbedBuilder()
          .setTitle('🌐 AUTO-TRANSLATION')
          .setDescription(`
**Non-English messages are auto-translated:**
• Original message shown
• English translation below
• Your replies are translated back to their language

**Language shown in ticket header**
          `)
          .setColor(CONFIG.COLORS.info);
        
        const guideEmbed5 = new EmbedBuilder()
          .setTitle('🎭 MOOD & REPUTATION')
          .setDescription(`
**AI Mood Detection:**
😡 Angry | 😤 Frustrated | 😢 Upset | 😐 Neutral | 😊 Friendly

**Auto-Escalation:** Angry/critical messages ping staff immediately

**User Reputation:**
⭐ Trusted (80+) - Good history
😐 Neutral (50-79) - Normal
⚠️ Caution (20-49) - Some issues
🚨 Problematic (<20) - Frequent problems

**Use +Rep / -Rep buttons** to adjust scores
          `)
          .setColor(CONFIG.COLORS.success);
        
        const guideEmbed6 = new EmbedBuilder()
          .setTitle('⌨️ COMMANDS')
          .addFields(
            { name: '💬 In Ticket Channels', value: `
\`?close [reason]\` - Close ticket & burn messages
\`?closeandkick [reason]\` - Close, burn, AND kick user
\`?claim\` - Mark ticket as yours
\`+Rep / -Rep buttons\` - Adjust user reputation
            `, inline: false },
            { name: '📤 In #staff-dm', value: `
\`?dm @user message\` - DM user (shows preview first)
            `, inline: false },
            { name: '📋 Anywhere', value: `
\`?tickets\` - View all open tickets
\`?blacklist @user\` - Block from modmail
\`?unblacklist @user\` - Unblock user
            `, inline: false }
          )
          .setColor(CONFIG.COLORS.success);
        
        const guideEmbed7 = new EmbedBuilder()
          .setTitle('⚖️ BAN APPEAL SYSTEM')
          .setDescription(`
**When someone is banned:**
1. They get DM with appeal instructions
2. They reply with \`APPEAL: [explanation]\`
3. AI reviews their appeal
4. You get notification with AI recommendation
5. Click ✅ Approve or ❌ Deny

**AI checks for:**
• Sincerity of apology
• Understanding of rules
• Red flags (excuses, lies)
• Positive factors
          `)
          .setColor(CONFIG.COLORS.warning);
        
        const guideEmbed8 = new EmbedBuilder()
          .setTitle('🔥 BURNER STYLE')
          .setDescription(`
**When you close a ticket:**
• Transcript saved to logs
• User notified of closure
• ALL bot messages **DELETED** from their DMs
• Ticket channel deleted
• Only their own messages remain

**Always close BEFORE kicking!**
Use \`?closeandkick\` to do both safely.
          `)
          .setColor(CONFIG.COLORS.error);
        
        const guideEmbed9 = new EmbedBuilder()
          .setTitle('⚠️ SECURITY ALERTS')
          .setDescription(`
**Critical threats are auto-reported:**
• Death threats
• Doxxing attempts
• Swatting mentions

**Scam patterns flagged:**
• "Free Nitro" links
• Fake Discord domains
• Phishing attempts

**Trust the system - don't click suspicious links!**
          `)
          .setColor(CONFIG.COLORS.danger)
          .setFooter({ text: 'Burner Phone ULTIMATE • The Unpatched Method • Stay Safe' });
        
        await guide.send({ embeds: [guideEmbed1, guideEmbed2, guideEmbed3, guideEmbed4, guideEmbed5] });
        await guide.send({ embeds: [guideEmbed6, guideEmbed7, guideEmbed8, guideEmbed9] });
      }
      
      await message.reply(`✅ Modmail ULTIMATE ready!\n📁 Category: ${cat.name}\n📋 Logs: ${log}\n💬 Staff DM: ${staffDm}\n📖 Guide: ${guide}`);
    }
    
    // ?modmailguide
    if (cmd === 'modmailguide' && isStaff(message.member)) {
      const guide = new EmbedBuilder()
        .setTitle('📖 BURNER PHONE - STAFF GUIDE')
        .setDescription('How to use the modmail system')
        .addFields(
          { name: '📨 How It Works', value: 'User DMs me → Ticket created → You reply in ticket channel → User gets DM' },
          { name: '💬 Commands', value: `
\`?dm @user message\` - DM any user
\`?close [reason]\` - Close ticket
\`?claim\` - Claim ticket
\`?tickets\` - View open tickets
\`?blacklist @user\` - Block user
\`?unblacklist @user\` - Unblock user
          ` },
          { name: '🔘 Buttons', value: '✋ Claim - Mark as yours\n🔒 Close - Close ticket\n⚡ Priority - Change urgency' }
        )
        .setColor(CONFIG.COLORS.primary);
      
      await message.reply({ embeds: [guide] });
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
  if (!isStaff(interaction.member)) return interaction.reply({ content: '❌ Staff only.', ephemeral: true });
  
  if (interaction.customId === 'claim') {
    if (ticket.claimed_by) return interaction.reply({ content: `Already claimed by <@${ticket.claimed_by}>`, ephemeral: true });
    await pool.query(`UPDATE modmail_tickets SET claimed_by = $1 WHERE id = $2`, [interaction.user.id, ticket.id]);
    await interaction.reply(`✋ Claimed by ${interaction.user}`);
  }
  
  if (interaction.customId === 'close') {
    await interaction.reply('🔒 Closing ticket...');
    
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
      await user.send({ embeds: [new EmbedBuilder().setTitle('🔒 Ticket Closed').setDescription('Your ticket has been resolved.\n\n*This conversation will be deleted shortly.*').setColor(CONFIG.COLORS.error)] });
      
      await interaction.channel.send('🔥 Burning messages...');
      
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
        .setTitle(`🔒 Ticket #${ticket.ticket_number} Closed`)
        .addFields(
          { name: '👤 User', value: `<@${ticket.user_id}>`, inline: true },
          { name: '👮 Closed By', value: interaction.user.tag, inline: true },
          { name: '📅 Opened', value: `<t:${Math.floor(new Date(ticket.created_at).getTime() / 1000)}:R>`, inline: true }
        )
        .setColor(CONFIG.COLORS.warning)
        .setTimestamp();
      
      const transcriptBuffer = Buffer.from(transcript, 'utf-8');
      await logChannel.send({ 
        embeds: [logEmbed], 
        files: [{ attachment: transcriptBuffer, name: `ticket-${ticket.ticket_number}-transcript.txt` }] 
      });
    }
    
    await interaction.channel.send('✅ Transcript saved. Deleting channel in 5 seconds...');
    setTimeout(() => interaction.channel.delete().catch(() => {}), 5000);
  }
  
  if (interaction.customId === 'priority') {
    await interaction.reply({
      content: 'Select priority:',
      components: [new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId('p_high').setLabel('🔴 High').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId('p_normal').setLabel('🟡 Normal').setStyle(ButtonStyle.Primary),
        new ButtonBuilder().setCustomId('p_low').setLabel('🟢 Low').setStyle(ButtonStyle.Success)
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
      return interaction.update({ content: '❌ Message expired. Please try again.', embeds: [], components: [] });
    }
    
    try {
      const { user, content, guild, originalMsg, preview } = pending;
      
      // Check if user already has open ticket
      let ticket = await getOpenTicket(user.id);
      
      if (!ticket) {
        // Create ticket for this outreach
        const ticketNum = await getNextTicketNumber();
        
        // Find or create category
        let category = guild.channels.cache.find(c => c.name === '📨 MODMAIL' && c.type === ChannelType.GuildCategory);
        if (!category) {
          category = await guild.channels.create({
            name: '📨 MODMAIL',
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
          .setTitle(`📨 Ticket #${ticketNum} (Staff Initiated)`)
          .setDescription(`**User:** ${user} (${user.tag})\n**ID:** ${user.id}\n**Started by:** ${interaction.user.tag}`)
          .setColor(CONFIG.COLORS.primary)
          .setThumbnail(user.displayAvatarURL())
          .setTimestamp();
        
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId('claim').setLabel('Claim').setStyle(ButtonStyle.Primary).setEmoji('✋'),
          new ButtonBuilder().setCustomId('close').setLabel('Close').setStyle(ButtonStyle.Danger).setEmoji('🔒'),
          new ButtonBuilder().setCustomId('priority').setLabel('Priority').setStyle(ButtonStyle.Secondary).setEmoji('⚡')
        );
        
        await channel.send({ embeds: [embed], components: [row] });
      }
      
      // Save outgoing message
      await pool.query(`
        INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
        VALUES ($1, $2, $3, $4, true)
      `, [ticket.id, interaction.user.id, interaction.user.tag, content]);
      
      // DM the user
      const dmEmbed = new EmbedBuilder()
        .setTitle('📬 Message from The Unpatched Method Team')
        .setDescription(content)
        .setColor(CONFIG.COLORS.primary)
        .setFooter({ text: 'Reply to this DM to respond' })
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
      const confirm = await interaction.channel.send(`✅ Message sent to ${user.tag} - Ticket: <#${ticket.channel_id}>`);
      setTimeout(() => confirm.delete().catch(() => {}), 5000);
      
      // Clean up
      client.pendingDMs.delete(key);
    } catch (e) {
      await interaction.update({ content: `❌ Could not DM user - they may have DMs disabled.`, embeds: [], components: [] });
      client.pendingDMs.delete(key);
    }
  }
});

// Handle ticket confirmation from DMs
client.on(Events.InteractionCreate, async (interaction) => {
  if (!interaction.isButton()) return;
  
  // Only handle in DMs
  if (interaction.channel.type !== ChannelType.DM) return;
  
  if (interaction.customId === 'cancel_ticket') {
    client.pendingTickets?.delete(interaction.user.id);
    await interaction.update({ 
      content: '❌ Cancelled. Your message was not sent.', 
      embeds: [], 
      components: [] 
    });
    return;
  }
  
  if (interaction.customId === 'confirm_ticket') {
    const pending = client.pendingTickets?.get(interaction.user.id);
    
    if (!pending) {
      return interaction.reply({ 
        content: '❌ Session expired. Please send your message again.', 
        ephemeral: true 
      });
    }
    
    // Defer the reply - this gives us 15 minutes to respond
    await interaction.deferUpdate();
    
    try {
      const { content, guild, user, translation, mood, reputation, linkResults, scamThreats, existingTicket } = pending;
      
      if (existingTicket) {
        // Add to existing ticket
        const channel = guild.channels.cache.get(existingTicket.channel_id);
        if (channel) {
          await pool.query(`
            INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, original_content, detected_language, is_staff)
            VALUES ($1, $2, $3, $4, $5, $6, false)
          `, [existingTicket.id, user.id, user.tag, translation?.translated || content, content, translation?.languageCode || 'en']);
          
          // Build embed with all info
          const embed = new EmbedBuilder()
            .setAuthor({ name: user.tag, iconURL: user.displayAvatarURL() })
            .setDescription(content)
            .setColor(CONFIG.COLORS.info)
            .setTimestamp();
          
          // Add translation if not English
          if (translation?.translated && !translation.isEnglish) {
            embed.addFields({ 
              name: `🌐 Translated from ${translation.language}`, 
              value: translation.translated.slice(0, 1024),
              inline: false 
            });
          }
          
          // Add mood indicator
          if (mood) {
            embed.addFields({ 
              name: 'Mood', 
              value: `${mood.emoji} ${mood.mood} | Urgency: ${mood.urgency}`, 
              inline: true 
            });
          }
          
          // Add link scan results
          if (linkResults && linkResults.length > 0) {
            const linkStatus = linkResults.map(r => 
              `${r.safe ? '✅' : '🚨'} ${r.url.slice(0, 50)}${r.url.length > 50 ? '...' : ''}`
            ).join('\n');
            embed.addFields({ name: '🔗 Links Scanned', value: linkStatus.slice(0, 1024), inline: false });
            
            const unsafeLinks = linkResults.filter(r => !r.safe);
            if (unsafeLinks.length > 0) {
              const threatDetails = unsafeLinks.flatMap(r => r.threats).join('\n• ');
              embed.addFields({ name: '⚠️ THREATS DETECTED', value: `• ${threatDetails}`, inline: false });
              embed.setColor(CONFIG.COLORS.danger);
            }
          }
          
          // Add scam warning
          if (scamThreats && scamThreats.length > 0) {
            embed.addFields({ name: '🚨 SCAM PATTERNS', value: scamThreats.join('\n').slice(0, 1024), inline: false });
            embed.setColor(CONFIG.COLORS.danger);
          }
          
          await channel.send({ embeds: [embed] });
          
          // Alert if escalation needed
          if (mood?.escalate) {
            await channel.send(`⚠️ **AUTO-ESCALATION**: ${mood.reason}`);
          }
          
          const successEmbed = new EmbedBuilder()
            .setTitle('✅ Message Sent!')
            .setDescription('Your message has been added to your ticket. Staff will respond soon.')
            .setColor(CONFIG.COLORS.success)
            .setFooter({ text: 'The Unpatched Method • Support' });
          
          await interaction.editReply({ content: null, embeds: [successEmbed], components: [] });
        }
      } else {
        // Create new ticket
        const ticket = await createTicket(user, guild, content, {
          translation,
          mood,
          reputation,
          linkResults,
          scamThreats
        });
        
        const successEmbed = new EmbedBuilder()
          .setTitle('📨 Ticket Created!')
          .setDescription(`Your ticket **#${ticket.ticket_number}** has been created.\n\nStaff will respond soon. Just reply here to add more info.`)
          .setColor(CONFIG.COLORS.success)
          .setFooter({ text: 'The Unpatched Method • Support' });
        
        await interaction.editReply({ content: null, embeds: [successEmbed], components: [] });
      }
      
      client.pendingTickets.delete(interaction.user.id);
    } catch (e) {
      console.error('Ticket creation error:', e);
      await interaction.editReply({ content: '❌ Error creating ticket. Please try again.', embeds: [], components: [] });
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
      .setTitle('⚠️ VERIFY YOURSELF ⚠️')
      .setDescription(`# 🚨 YOU MUST VERIFY TO ACCESS THE SERVER 🚨\n\nHey **${member.user.username}**, welcome to **The Unpatched Method**.\n\n**You NEED to verify before you can see channels.**`)
      .addFields(
        { name: '✅ HOW TO VERIFY', value: `**1.** Click here → ${verifyLink}\n**2.** Click the ✅ button\n**3.** Done!` },
        { name: '❌ WITHOUT VERIFICATION', value: '• Can\'t see channels\n• Can\'t chat\n• Can\'t join LFG', inline: true },
        { name: '✅ AFTER VERIFICATION', value: '• Full server access\n• LFG for heists\n• Talk to bots', inline: true }
      )
      .setColor(0xFF0000);
    
    const embed2 = new EmbedBuilder()
      .setTitle('🎮 Welcome to The Unpatched Method!')
      .setDescription('Once verified:')
      .addFields(
        { name: '🎯 LFG Channels', value: '• #cayo-lfg\n• #wagon-lfg\n• #bounty-lfg' },
        { name: '💡 Pro Tip', value: 'Type `?daily` in #casino for free chips!' },
        { name: '📩 Need Help?', value: '**DM me anytime** to talk to staff!' }
      )
      .setColor(CONFIG.COLORS.primary)
      .setThumbnail(guild.iconURL());
    
    await member.send({ content: '# 🚨 READ THIS FIRST 🚨', embeds: [embed1, embed2] });
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
        .setTitle('✅ You\'re Verified!')
        .setDescription(`Welcome **${newMember.user.username}**! Here's what to do:`)
        .addFields(
          { name: '🎯 STEP 1: Pick Roles', value: `Go to <#${CONFIG.ROLES_CHANNEL_ID}> and select your games/platform` },
          { name: '🎮 STEP 2: Find Crew', value: '• #cayo-lfg - GTA heists\n• #wagon-lfg - RDO trading\n• #bounty-lfg - Bounties' },
          { name: '💰 STEP 3: Free Stuff', value: 'Type `?daily` in #casino for free chips!' },
          { name: '📩 Need Help?', value: '**DM me** to create a support ticket!' }
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
    
    // Send appeal information to banned user
    const appealEmbed = new EmbedBuilder()
      .setTitle('⛔ You Have Been Banned')
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
      return message.reply('❌ Your appeal is too short. Please provide a detailed explanation.');
    }
    
    // Get ban info
    const banInfo = await pool.query(`
      SELECT * FROM ban_appeals WHERE user_id = $1 AND status IN ('awaiting', 'pending')
      ORDER BY created_at DESC LIMIT 1
    `, [message.author.id]);
    
    if (banInfo.rows.length === 0) {
      return message.reply('❌ No pending ban found for your account.');
    }
    
    const ban = banInfo.rows[0];
    
    // Process with AI
    await message.reply('🔄 Processing your appeal with AI review...');
    
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
        .setTitle('📋 New Ban Appeal')
        .setDescription(`**User:** ${message.author.tag} (${message.author.id})`)
        .addFields(
          { name: '⛔ Ban Reason', value: ban.ban_reason || 'Not specified', inline: false },
          { name: '📝 Appeal', value: appealText.slice(0, 1024), inline: false },
          { name: '🤖 AI Recommendation', value: `**${aiResult.recommendation.toUpperCase()}** (${aiResult.confidence}% confidence)`, inline: true },
          { name: '📊 AI Reasoning', value: aiResult.reasoning?.slice(0, 1024) || 'N/A', inline: false }
        )
        .setColor(
          aiResult.recommendation === 'approve' ? CONFIG.COLORS.success :
          aiResult.recommendation === 'deny' ? CONFIG.COLORS.error : CONFIG.COLORS.warning
        )
        .setTimestamp();
      
      if (aiResult.redFlags?.length > 0) {
        appealEmbed.addFields({ name: '🚩 Red Flags', value: aiResult.redFlags.join('\n'), inline: true });
      }
      if (aiResult.positiveFactors?.length > 0) {
        appealEmbed.addFields({ name: '✅ Positive Factors', value: aiResult.positiveFactors.join('\n'), inline: true });
      }
      
      const row = new ActionRowBuilder().addComponents(
        new ButtonBuilder().setCustomId(`appeal_approve_${ban.id}`).setLabel('✅ Approve & Unban').setStyle(ButtonStyle.Success),
        new ButtonBuilder().setCustomId(`appeal_deny_${ban.id}`).setLabel('❌ Deny').setStyle(ButtonStyle.Danger),
        new ButtonBuilder().setCustomId(`appeal_questions_${ban.id}`).setLabel('❓ Need More Info').setStyle(ButtonStyle.Secondary)
      );
      
      await logChannel.send({ content: '@here Ban appeal received', embeds: [appealEmbed], components: [row] });
    }
    
    // Confirm to user
    const confirmEmbed = new EmbedBuilder()
      .setTitle('✅ Appeal Submitted')
      .setDescription(`
Your appeal has been received and is being reviewed.

**AI Pre-Assessment:** ${aiResult.recommendation === 'approve' ? '✅ Favorable' : aiResult.recommendation === 'deny' ? '❌ Unfavorable' : '⏳ Needs Review'}

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
        .setTitle('✅ Appeal Approved!')
        .setDescription('Your ban appeal has been approved. You may rejoin the server.\n\n**Please follow the rules this time.**')
        .setColor(CONFIG.COLORS.success)
      ]});
      
      await interaction.update({ content: `✅ Appeal approved by ${interaction.user.tag}. User unbanned.`, components: [] });
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
        .setTitle('❌ Appeal Denied')
        .setDescription('Your ban appeal has been denied. The ban will remain in place.\n\nYou may submit another appeal in 30 days.')
        .setColor(CONFIG.COLORS.error)
      ]});
    } catch (e) {}
    
    await interaction.update({ content: `❌ Appeal denied by ${interaction.user.tag}.`, components: [] });
  }
  
  // Reputation buttons
  if (interaction.customId === 'rep_good') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    await updateReputation(ticket.user_id, 5, 'Good interaction');
    await interaction.reply({ content: '👍 User reputation increased (+5)', ephemeral: true });
  }
  
  if (interaction.customId === 'rep_bad') {
    const ticket = await getTicketByChannel(interaction.channel.id);
    if (!ticket) return;
    await updateReputation(ticket.user_id, -10, 'Bad interaction');
    await interaction.reply({ content: '👎 User reputation decreased (-10)', ephemeral: true });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// READY
// ═══════════════════════════════════════════════════════════════════════════════

client.once(Events.ClientReady, async () => {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║      BURNER PHONE - ULTIMATE SECURITY SYSTEM              ║');
  console.log('║      AI • Translation • Link Scanning • Appeals           ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log(`Logged in as ${client.user.tag}`);
  
  await initDatabase();
  
  client.user.setPresence({
    activities: [{ name: 'DM me for support | 🔒 Secure', type: 3 }],
    status: 'online'
  });
});

client.login(process.env.DISCORD_TOKEN);
