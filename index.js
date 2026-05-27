/* jslint es6:true, node:true */
'use strict';

require('dotenv').config();

const { connectDB, closeDB }                          = require('./src/db');
const { seedSampleData }                              = require('./src/seed');
const { checkBlacklist, addToBlacklist,
        removeBlacklistEntry }                        = require('./src/blacklist');
const { listIncidents, createIncident,
        updateIncidentStatus }                        = require('./src/incidents');

const argv = process.argv.slice(2);
const cmd  = argv[0];

// ── Help Text ──────────────────────────────────────────────────────────────────
const HELP = `
╔══════════════════════════════════════════════════════════════╗
║           PhishPhalanx — Threat Intelligence CLI            ║
╠══════════════════════════════════════════════════════════════╣
║  USAGE: node index.js <command> [args]                       ║
╠══════════════════════════════════════════════════════════════╣
║  seed:blacklists                     Seed sample data       ║
║  check-domain    <domain>            Check if blacklisted   ║
║  add-blacklist   <domain> [type]     Add domain to list     ║
║  remove-blacklist <domain>           Remove from list       ║
║  list-incidents  [danger] [status]   List incidents         ║
║  create-incident <danger> [email] [domain] Report new incident ║
║  update-incident <INC-ID> <status>  Update incident status  ║
║  help                                Show this menu         ║
╚══════════════════════════════════════════════════════════════╝
`;

// ── Main Entry Point ───────────────────────────────────────────────────────────

/**
 * Main CLI entrypoint for PhishPhalanx.
 * Connects to MongoDB Atlas, routes to the appropriate module, then disconnects.
 */
async function main() {
  if (!cmd || cmd === 'help') {
    console.log(HELP);
    return;
  }

  // Establish Mongoose connection before any DB operations
  await connectDB();

  try {
    // ── seed:blacklists ──────────────────────────────────────────────────────
    if (cmd === 'seed:blacklists') {
      const res = await seedSampleData();
      console.log('🎉 Seeding complete:', res);
    }

    // ── check-domain <domain> ────────────────────────────────────────────────
    else if (cmd === 'check-domain') {
      const domain = argv[1];
      if (!domain) { console.error('⚠️  Please provide a domain.'); return; }
      const res = await checkBlacklist(domain);
      if (res.blacklisted) {
        console.log(`🚨 BLACKLISTED: ${domain}`);
        console.log('   Entry:', res.document);
      } else {
        console.log(`✅ CLEAN: ${domain} is not on the blacklist.`);
      }
    }

    // ── add-blacklist <domain> [malwareType] ─────────────────────────────────
    else if (cmd === 'add-blacklist') {
      const domain      = argv[1];
      const malwareType = argv[2] || 'phishing';
      if (!domain) { console.error('⚠️  Please provide a domain.'); return; }
      const doc = await addToBlacklist(domain, malwareType);
      console.log('✅ Added to blacklist:', doc);
    }

    // ── remove-blacklist <domain> ────────────────────────────────────────────
    else if (cmd === 'remove-blacklist') {
      const domain = argv[1];
      if (!domain) { console.error('⚠️  Please provide a domain.'); return; }
      await removeBlacklistEntry(domain);
      console.log(`🗑️  Removed "${domain}" from blacklist.`);
    }

    // ── create-incident <dangerLevel> [reporterEmail] [targetDomain] ──────────
    else if (cmd === 'create-incident') {
      const dangerLevel   = argv[1] || 'low';
      const reporterEmail = argv[2] || 'cli-analyst@phishphalanx.local';
      const targetDomain  = argv[3] || 'unknown';
      const incident = await createIncident({ dangerLevel, reporterEmail, targetDomain });
      console.log('✅ Incident created:', incident);
    }

    // ── list-incidents [dangerLevel] [status] ────────────────────────────────
    else if (cmd === 'list-incidents') {
      const dangerLevel = argv[1];
      const status      = argv[2];
      const results     = await listIncidents({ dangerLevel, status });
      if (results.length === 0) {
        console.log('ℹ️  No incidents found matching the given filters.');
      } else {
        console.log(`📋 Found ${results.length} incident(s):`);
        results.forEach((inc, i) => {
          console.log(`\n  [${i + 1}] ${inc.incidentId} | ${inc.dangerLevel.toUpperCase()} | ${inc.status}`);
          console.log(`       Domain : ${inc.targetDomain || 'N/A'}`);
          console.log(`       Reporter: ${inc.reporterEmail || 'N/A'}`);
          console.log(`       Time   : ${new Date(inc.timestamp).toISOString()}`);
        });
      }
    }

    // ── update-incident <incidentId> <newStatus> ─────────────────────────────
    else if (cmd === 'update-incident') {
      const incidentId = argv[1];
      const newStatus  = argv[2];
      if (!incidentId || !newStatus) {
        console.error('⚠️  Usage: node index.js update-incident <INC-ID> <status>');
        return;
      }
      await updateIncidentStatus(incidentId, newStatus);
      console.log(`✅ Incident ${incidentId} updated to status: "${newStatus}"`);
    }

    // ── Unknown command ──────────────────────────────────────────────────────
    else {
      console.log(`❓ Unknown command: "${cmd}"\n`);
      console.log(HELP);
    }

  } catch (err) {
    console.error('💥 Command failed:', err.message);
    process.exitCode = 1;
  } finally {
    await closeDB();
  }
}

if (require.main === module) main();
