/* jslint es6:true, node:true */
require('dotenv').config();
const argv = process.argv.slice(2);
const { seedSampleData } = require('./src/seed');
const { checkBlacklist, addToBlacklist, removeBlacklistEntry } = require('./src/blacklist');
const { getIncidentsByFilter } = require('./src/incidents');

/**
 * Main CLI entrypoint for PhishPhalanx.
 * Parses commands and routes to the appropriate module operations.
 */
async function main() {
  const cmd = argv[0];
  if (!cmd || cmd === 'help') {
      console.log('Usage: node index.js <command> [args]\nCommands: seed:blacklists | check-domain <domain> | add-blacklist <domain> | remove-blacklist <domain> | list-incidents [danger] [status]');
  }

  try {
    if (cmd === 'seed:blacklists') {
      await seedSampleData();
      console.log('Sample data seeded');
      return;
    }

    if (cmd === 'check-domain') {
      const domain = argv[1];
      const res = await checkBlacklist(domain);
      console.log(res.blacklisted ? 'BLACKLISTED' : 'clean', res.document);
      return;
    }

    if (cmd === 'add-blacklist') {
      const domain = argv[1];
      const id = await addToBlacklist(domain);
      console.log('Added blacklist doc:', id);
      return;
    }

    if (cmd === 'remove-blacklist') {
      const domain = argv[1];
      await removeBlacklistEntry(domain);
      console.log('Removed blacklist entry for', domain);
      return;
    }

    if (cmd === 'list-incidents') {
      const danger = argv[1];
      const status = argv[2];
      const results = await getIncidentsByFilter({ dangerLevel: danger, status });
      console.log('Incidents:', results);
      return;
    }

    console.log('Unknown command:', cmd);
  } catch (err) {
    console.error('Command failed:', err);
    process.exitCode = 1;
  }
}

if (require.main === module) main();
