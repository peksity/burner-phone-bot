/**
 * ██████╗ ██╗   ██╗██████╗ ███╗   ██╗███████╗██████╗     ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗███████╗
 * ██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝██╔══██╗    ██╔══██╗██║  ██║██╔═══██╗████╗  ██║██╔════╝
 * ██████╔╝██║   ██║██████╔╝██╔██╗ ██║█████╗  ██████╔╝    ██████╔╝███████║██║   ██║██╔██╗ ██║█████╗  
 * ██╔══██╗██║   ██║██╔══██╗██║╚██╗██║██╔══╝  ██╔══██╗    ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║██╔══╝  
 * ██████╔╝╚██████╔╝██║  ██║██║ ╚████║███████╗██║  ██║    ██║     ██║  ██║╚██████╔╝██║ ╚████║███████╗
 * ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
 * 
 * BURNER PHONE - Modmail & Support System
 * All DMs go through this bot
 */

require('dotenv').config();
const { 
  Client, GatewayIntentBits, Partials, EmbedBuilder, 
  PermissionFlagsBits, Events, ActionRowBuilder, ButtonBuilder, 
  ButtonStyle, ChannelType, StringSelectMenuBuilder
} = require('discord.js');
const { Pool } = require('pg');

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
    GatewayIntentBits.GuildMembers,
    GatewayIntentBits.DirectMessages
  ],
  partials: [Partials.Channel, Partials.Message, Partials.User]
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ═══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════════════════════════════════

const CONFIG = {
  PREFIX: '?',
  GUILD_ID: '1446317951757062256',
  VERIFIED_ROLE_ID: '1453304594317836423',
  ROLES_CHANNEL_ID: '1453304724681134163',
  COLORS: { primary: 0xFF6B35, success: 0x00FF00, error: 0xFF0000, warning: 0xFFAA00, info: 0x0099FF }
};

// ═══════════════════════════════════════════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════════════════════════════════════════

async function initDatabase() {
  // Drop old tables if they have wrong schema
  await pool.query(`DROP TABLE IF EXISTS modmail_messages CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS modmail_tickets CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS modmail_blacklist CASCADE`);
  await pool.query(`DROP TABLE IF EXISTS modmail_canned CASCADE`);
  
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
      created_at TIMESTAMP DEFAULT NOW(),
      closed_at TIMESTAMP,
      closed_by TEXT,
      close_reason TEXT
    )
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS modmail_messages (
      id SERIAL PRIMARY KEY,
      ticket_id INT,
      author_id TEXT NOT NULL,
      author_name TEXT NOT NULL,
      content TEXT NOT NULL,
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
  console.log('[DB] Tables ready');
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
// TICKET CREATION
// ═══════════════════════════════════════════════════════════════════════════════

async function createTicket(user, guild, message) {
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
    topic: `User: ${user.tag} (${user.id})`
  });
  
  // Save to DB
  const r = await pool.query(`
    INSERT INTO modmail_tickets (ticket_number, user_id, guild_id, channel_id)
    VALUES ($1, $2, $3, $4) RETURNING *
  `, [ticketNum, user.id, guild.id, channel.id]);
  const ticket = r.rows[0];
  
  await pool.query(`
    INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
    VALUES ($1, $2, $3, $4, false)
  `, [ticket.id, user.id, user.tag, message]);
  
  // Ticket embed
  const embed = new EmbedBuilder()
    .setTitle(`📨 Ticket #${ticketNum}`)
    .setDescription(`**User:** ${user} (${user.tag})\n**ID:** ${user.id}`)
    .addFields({ name: '📝 Message', value: message.slice(0, 1024) || 'No message' })
    .setColor(CONFIG.COLORS.primary)
    .setThumbnail(user.displayAvatarURL())
    .setTimestamp();
  
  const row = new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId('claim').setLabel('Claim').setStyle(ButtonStyle.Primary).setEmoji('✋'),
    new ButtonBuilder().setCustomId('close').setLabel('Close').setStyle(ButtonStyle.Danger).setEmoji('🔒'),
    new ButtonBuilder().setCustomId('priority').setLabel('Priority').setStyle(ButtonStyle.Secondary).setEmoji('⚡')
  );
  
  await channel.send({ content: '@here New ticket!', embeds: [embed], components: [row] });
  
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
    
    let ticket = await getOpenTicket(message.author.id);
    
    if (ticket) {
      // Add to existing ticket
      const channel = guild.channels.cache.get(ticket.channel_id);
      if (channel) {
        await pool.query(`
          INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
          VALUES ($1, $2, $3, $4, false)
        `, [ticket.id, message.author.id, message.author.tag, message.content]);
        
        const embed = new EmbedBuilder()
          .setAuthor({ name: message.author.tag, iconURL: message.author.displayAvatarURL() })
          .setDescription(message.content)
          .setColor(CONFIG.COLORS.info)
          .setTimestamp();
        
        await channel.send({ embeds: [embed] });
        await message.react('✅');
      }
    } else {
      // Create new ticket
      ticket = await createTicket(message.author, guild, message.content);
      
      const confirmEmbed = new EmbedBuilder()
        .setTitle('📨 Ticket Created!')
        .setDescription(`Your ticket **#${ticket.ticket_number}** has been created.\n\nStaff will respond soon. Just reply here to add more info.`)
        .setColor(CONFIG.COLORS.success);
      
      await message.reply({ embeds: [confirmEmbed] });
    }
    return;
  }
  
  // Ticket channel = staff reply
  if (message.guild && message.channel.name?.startsWith('ticket-')) {
    const ticket = await getTicketByChannel(message.channel.id);
    if (!ticket || message.content.startsWith(CONFIG.PREFIX)) return;
    if (!isStaff(message.member)) return;
    
    await pool.query(`
      INSERT INTO modmail_messages (ticket_id, author_id, author_name, content, is_staff)
      VALUES ($1, $2, $3, $4, true)
    `, [ticket.id, message.author.id, message.author.tag, message.content]);
    
    try {
      const user = await client.users.fetch(ticket.user_id);
      const embed = new EmbedBuilder()
        .setTitle('📬 Staff Response')
        .setDescription(message.content)
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
      await pool.query(`UPDATE modmail_tickets SET status = 'closed', closed_at = NOW(), closed_by = $1, close_reason = $2 WHERE id = $3`,
        [message.author.id, reason, ticket.id]);
      
      try {
        const user = await client.users.fetch(ticket.user_id);
        
        // Send closing message
        await user.send({ embeds: [new EmbedBuilder().setTitle('🔒 Ticket Closed').setDescription(`Reason: ${reason}\n\n*This conversation will be deleted shortly.*`).setColor(CONFIG.COLORS.error)] });
        
        // Delete bot's messages from user's DMs (burner style)
        try {
          const dmChannel = await user.createDM();
          const messages = await dmChannel.messages.fetch({ limit: 100 });
          const botMessages = messages.filter(m => m.author.id === client.user.id);
          
          for (const [, msg] of botMessages) {
            await msg.delete().catch(() => {});
            await new Promise(r => setTimeout(r, 500)); // Rate limit protection
          }
        } catch (e) {
          console.log('Could not delete DM messages:', e.message);
        }
      } catch (e) {}
      
      // Log to modmail-logs
      await logToModmail(message.guild, ticket, message.author, reason);
      
      await message.channel.send('🔒 Closing in 5 seconds... Messages burned 🔥');
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
          topic: 'How to use the Burner Phone modmail system'
        });
        
        // Send the guide
        const guideEmbed1 = new EmbedBuilder()
          .setTitle('📱 BURNER PHONE - STAFF GUIDE')
          .setDescription('This is your secure modmail system. All staff-to-member communication goes through this bot so you never have to use your personal DMs.')
          .setColor(CONFIG.COLORS.primary)
          .setImage('https://i.imgur.com/8QqZQqN.png');
        
        const guideEmbed2 = new EmbedBuilder()
          .setTitle('📥 WHEN A USER DMS THE BOT')
          .setDescription(`
**What happens:**
1. User sends a DM to Burner Phone
2. A ticket channel is created here (ticket-0001, etc.)
3. You see their message in the ticket
4. Just type in the ticket channel to reply
5. They receive your reply as a DM

**They never see your name - it's all anonymous!**
          `)
          .setColor(CONFIG.COLORS.info);
        
        const guideEmbed3 = new EmbedBuilder()
          .setTitle('📤 WHEN YOU NEED TO DM A USER')
          .setDescription(`
**Go to #staff-dm and use:**
\`?dm @user Your message here\`

**What happens:**
1. User gets a DM from Burner Phone
2. A ticket is created to track replies
3. If they respond, it shows up in the ticket
          `)
          .setColor(CONFIG.COLORS.info);
        
        const guideEmbed4 = new EmbedBuilder()
          .setTitle('⌨️ COMMANDS')
          .addFields(
            { name: '💬 In Ticket Channels', value: `
\`?close [reason]\` - Close ticket & delete messages
\`?closeandkick [reason]\` - Close ticket, delete messages, AND kick user
\`?claim\` - Mark ticket as yours
            `, inline: false },
            { name: '📤 In #staff-dm', value: `
\`?dm @user message\` - DM a user through the bot
            `, inline: false },
            { name: '📋 Anywhere', value: `
\`?tickets\` - View all open tickets
\`?blacklist @user\` - Block user from modmail
\`?unblacklist @user\` - Unblock user
            `, inline: false }
          )
          .setColor(CONFIG.COLORS.success);
        
        const guideEmbed5 = new EmbedBuilder()
          .setTitle('🔥 BURNER STYLE')
          .setDescription(`
**When you close a ticket:**
• User gets a "Ticket Closed" message
• ALL bot messages in their DMs are **deleted**
• The ticket channel is deleted
• Only their own messages remain

**This protects both staff and the server!**
          `)
          .setColor(CONFIG.COLORS.warning);
        
        const guideEmbed6 = new EmbedBuilder()
          .setTitle('⚠️ IMPORTANT TIPS')
          .setDescription(`
• **Close BEFORE kicking** - Use \`?closeandkick\` to do both in the right order
• **Claim tickets** you're working on so others know
• **Check #modmail-logs** for ticket history
• **Never share your personal Discord** - use this system!
          `)
          .setColor(CONFIG.COLORS.error)
          .setFooter({ text: 'Burner Phone • The Unpatched Method' });
        
        await guide.send({ embeds: [guideEmbed1, guideEmbed2, guideEmbed3, guideEmbed4, guideEmbed5, guideEmbed6] });
      }
      
      await message.reply(`✅ Modmail ready!\n📁 Category: ${cat.name}\n📋 Logs: ${log}\n💬 Staff DM: ${staffDm}\n📖 Guide: ${guide}`);
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
    await pool.query(`UPDATE modmail_tickets SET status = 'closed', closed_at = NOW(), closed_by = $1 WHERE id = $2`, [interaction.user.id, ticket.id]);
    try {
      const user = await client.users.fetch(ticket.user_id);
      await user.send({ embeds: [new EmbedBuilder().setTitle('🔒 Ticket Closed').setDescription('Your ticket has been resolved.\n\n*This conversation will be deleted shortly.*').setColor(CONFIG.COLORS.error)] });
      
      // Delete bot's messages from user's DMs (burner style)
      try {
        const dmChannel = await user.createDM();
        const messages = await dmChannel.messages.fetch({ limit: 100 });
        const botMessages = messages.filter(m => m.author.id === client.user.id);
        
        for (const [, msg] of botMessages) {
          await msg.delete().catch(() => {});
          await new Promise(r => setTimeout(r, 500)); // Rate limit protection
        }
      } catch (e) {
        console.log('Could not delete DM messages:', e.message);
      }
    } catch (e) {}
    
    // Log to modmail-logs
    await logToModmail(interaction.guild, ticket, interaction.user, 'Closed via button');
    
    await interaction.reply('🔒 Closing... Messages burned 🔥');
    setTimeout(() => interaction.channel.delete().catch(() => {}), 3000);
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
// READY
// ═══════════════════════════════════════════════════════════════════════════════

client.once(Events.ClientReady, async () => {
  console.log('╔════════════════════════════════════════╗');
  console.log('║      BURNER PHONE - ONLINE             ║');
  console.log('╚════════════════════════════════════════╝');
  console.log(`Logged in as ${client.user.tag}`);
  
  await initDatabase();
  
  client.user.setPresence({
    activities: [{ name: 'DM me for support', type: 3 }],
    status: 'online'
  });
});

client.login(process.env.DISCORD_TOKEN);
