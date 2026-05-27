/* jslint es6:true, node:true */
'use strict';

require('dotenv').config();
const { connectDB, closeDB }                         = require('./db');
const { Incident }                                   = require('./incidents');
const { Blacklist, defangHostname, hashDomain,
        normalizeDomain }                            = require('./blacklist');

/**
 * Seed sample phishing incidents and blacklist entries into MongoDB Atlas.
 * Clears existing data first to prevent duplicate key errors on re-seeding.
 *
 * @returns {Promise<{ incidentsSeeded: number, blacklistSeeded: number }>}
 */
async function seedSampleData() {
  await connectDB();

  // ── Clear existing data ────────────────────────────────────────────────────
  await Incident.deleteMany({});
  await Blacklist.deleteMany({});
  console.log('🗑️  Cleared existing incidents and blacklist entries.');

  // ── Sample Incident Documents ──────────────────────────────────────────────
  const now = new Date();

  const incidents = [
    {
      incident_id:   'INC-1001',
      target_domain: defangHostname('secure-paypal-login.com'),
      danger_level:  'high',
      reporter_metadata: {
        analyst_id: 'analyst1@security.example',
        client_ip:  '192.168.1.50',
      },
      status:    'unresolved',
      createdAt: now,
    },
    {
      incident_id:   'INC-1002',
      target_domain: defangHostname('appleid.verify-account.org'),
      danger_level:  'medium',
      reporter_metadata: {
        analyst_id: 'analyst2@security.example',
        client_ip:  '192.168.1.51',
      },
      status:    'investigating',
      createdAt: now,
    },
    {
      incident_id:   'INC-1003',
      target_domain: defangHostname('office365-login-secure.net'),
      danger_level:  'high',
      reporter_metadata: {
        analyst_id: 'threat@company.local',
        client_ip:  '10.0.0.12',
      },
      status:    'unresolved',
      createdAt: now,
    },
    {
      incident_id:   'INC-1004',
      target_domain: defangHostname('bank-update-verify.com'),
      danger_level:  'critical',
      reporter_metadata: {
        analyst_id: 'fraud-team@bank.example',
        client_ip:  '172.16.254.1',
      },
      status:    'unresolved',
      createdAt: now,
    },
    {
      incident_id:   'INC-1005',
      target_domain: defangHostname('invoice-attachment-payments.biz'),
      danger_level:  'medium',
      reporter_metadata: {
        analyst_id: 'alerts@finance.example',
        client_ip:  '192.168.10.15',
      },
      status:    'resolved',
      createdAt: now,
    },
  ];

  await Incident.insertMany(incidents);
  console.log(`✅ Seeded ${incidents.length} incident(s).`);

  // ── Sample Blacklist Documents ─────────────────────────────────────────────
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
      _id:           hashDomain(normalized),
      target_domain: defangHostname(normalized),
      malware_type:  'phishing',
      date_added:    now,
    };
  });

  await Blacklist.insertMany(blacklistDocs);
  console.log(`✅ Seeded ${blacklistDocs.length} blacklist entry/entries.`);

  return { incidentsSeeded: incidents.length, blacklistSeeded: blacklistDocs.length };
}

module.exports = { seedSampleData };

// Run directly: node src/seed.js
if (require.main === module) {
  seedSampleData()
    .then(async (res) => {
      console.log('🎉 Seeding complete:', res);
      await closeDB();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('💥 Seeding failed:', err);
      await closeDB();
      process.exitCode = 1;
    });
}
