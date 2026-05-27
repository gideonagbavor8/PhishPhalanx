/* jslint es6:true, node:true */
require('dotenv').config();
const { getDb, closeDB } = require('./db');
const { defangHostname, hashDomain, normalizeDomain } = require('./blacklist');

/**
 * Seed sample phishing incident and blacklist documents into MongoDB.
 * @returns {Promise<{incidentsSeeded:number, blacklistSeeded:number}>}
 */
async function seedSampleData() {
  const db = await getDb();
  const now = new Date();

  // Clear existing data to prevent duplicate keys on re-seeding
  await db.collection('incidents').deleteMany({});
  await db.collection('blacklists').deleteMany({});

  // Sample incidents (realistic phishing examples)
  const incidents = [
    {
      incident_id: 'inc-1001',
      target_domain: defangHostname('secure-paypal-login.com'),
      danger_level: 'high',
      reporter_metadata: {
        analyst_id: 'analyst1@security.example',
        client_ip: '192.168.1.50',
      },
      status: 'unresolved',
      timestamp: now,
    },
    {
      incident_id: 'inc-1002',
      target_domain: defangHostname('appleid.verify-account.org'),
      danger_level: 'medium',
      reporter_metadata: {
        analyst_id: 'analyst2@security.example',
        client_ip: '192.168.1.51',
      },
      status: 'investigating',
      timestamp: now,
    },
    {
      incident_id: 'inc-1003',
      target_domain: defangHostname('office365-login-secure.net'),
      danger_level: 'high',
      reporter_metadata: {
        analyst_id: 'threat@company.local',
        client_ip: '10.0.0.12',
      },
      status: 'unresolved',
      timestamp: now,
    },
    {
      incident_id: 'inc-1004',
      target_domain: defangHostname('bank-update-verify.com'),
      danger_level: 'critical',
      reporter_metadata: {
        analyst_id: 'fraud-team@bank.example',
        client_ip: '172.16.254.1',
      },
      status: 'unresolved',
      timestamp: now,
    },
    {
      incident_id: 'inc-1005',
      target_domain: defangHostname('invoice-attachment-payments.biz'),
      danger_level: 'medium',
      reporter_metadata: {
        analyst_id: 'alerts@finance.example',
        client_ip: '192.168.10.15',
      },
      status: 'resolved',
      timestamp: now,
    },
  ];

  await db.collection('incidents').insertMany(incidents);

  // Sample blacklist entries
  const blacklistDomains = [
    'secure-paypal-login.com',
    'appleid.verify-account.org',
    'office365-login-secure.net',
    'bank-update-verify.com',
    'invoice-attachment-payments.biz',
  ];

  const blacklistDocs = blacklistDomains.map((d) => {
    const normalized = normalizeDomain(d);
    return {
      _id: hashDomain(normalized),
      target_domain: defangHostname(normalized),
      malware_type: 'phishing',
      date_added: now,
    };
  });

  await db.collection('blacklists').insertMany(blacklistDocs);

  return { incidentsSeeded: incidents.length, blacklistSeeded: blacklistDocs.length };
}

module.exports = { seedSampleData };

if (require.main === module) {
  seedSampleData()
    .then(async (res) => {
      console.log('Seeding complete', res);
      await closeDB();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('Seeding failed:', err);
      await closeDB();
      process.exitCode = 1;
    });
}
