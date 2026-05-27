/* jslint es6:true, node:true */
require('dotenv').config();
const argv = process.argv.slice(2);
const { seedSampleData } = require('./src/seed');
const { checkBlacklist, addToBlacklist, removeBlacklistEntry } = require('./src/blacklist');
const { listIncidents, createIncident } = require('./src/incidents');
const { closeDB } = require('./src/db');

/**
 * Main CLI entrypoint for PhishPhalanx.
 * Parses commands and routes to the appropriate module operations.
 */
async function main() {
  const cmd = argv[0];
  if (!cmd || cmd === 'help') {
      console.log('Usage: node index.js <command> [args]\nCommands: seed:blacklists | check-domain <domain> | add-blacklist <domain> | remove-blacklist <domain> | list-incidents [dangerLevel] [status] | create-incident [dangerLevel] [analystId] [clientIp]');
  }

  try {
    if (cmd === 'seed:blacklists') {
      await seedSampleData();
      return;
    }

    if (cmd === 'check-domain') {
      const domain = argv[1];
      const res = await checkBlacklist(domain);
      console.log(res.blacklisted ? 'BLACKLISTED' : 'clean', res.document);
    }

    else if (cmd === 'add-blacklist') {
      const domain = argv[1];
      const doc = await addToBlacklist(domain);
      console.log('Added blacklist doc:', doc);
    }

    else if (cmd === 'remove-blacklist') {
      const domain = argv[1];
      await removeBlacklistEntry(domain);
      console.log('Removed blacklist entry for', domain);
    }

    else if (cmd === 'create-incident') {
      const danger = argv[1];
      const analystId = argv[2] || 'analyst-cli';
      const clientIp = argv[3] || '127.0.0.1';

      const data = {
        dangerLevel: danger,
        analystId: analystId,
        clientIp: clientIp,
      };

      const result = await createIncident(data);
      console.log('Created Incident successfully:', result);
    }

    else if (cmd === 'list-incidents') {
      const danger = argv[1];
      const status = argv[2];
      const results = await listIncidents({ dangerLevel: danger, status: status });
      console.log('Incidents:', results);
    }

    else if (cmd && cmd !== 'help') {
      console.log('Unknown command:', cmd);
    }
  } catch (err) {
    console.error('Command failed:', err);
    process.exitCode = 1;
  } finally {
    // Ensure the MongoDB connection is closed so the Node process can exit.
    await closeDB();
  }
}

if (require.main === module) main();
