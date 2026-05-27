/* jslint es6:true, node:true */
'use strict';

/**
 * seed.js — Database Seeder for PhishPhalanx
 * ─────────────────────────────────────────────────────────────────────────────
 * Populates MongoDB Atlas with sample phishing incidents and blacklisted
 * domains for development, testing, and demonstration purposes.
 *
 * Run directly: node src/seed.js
 * Or via npm  : npm run seed
 * ─────────────────────────────────────────────────────────────────────────────
 */

require('dotenv').config();
const { connectDB, closeDB }                       = require('./db');
const Incident                                     = require('./models/Incident');
const Blacklist                                    = require('./models/Blacklist');
const { defangHostname, hashDomain, normalizeDomain } = require('./blacklist');

/**
 * seedSampleData()
 * Clears existing incidents and blacklist entries, then inserts fresh sample
 * data. Designed to be idempotent — safe to run multiple times.
 *
 * @returns {Promise<{ incidentsSeeded: number, blacklistSeeded: number }>}
 */
async function seedSampleData() {
  await connectDB();
  const now = new Date();

  // ── Clear existing data ────────────────────────────────────────────────────
  await Incident.deleteMany({});
  await Blacklist.deleteMany({});
  console.log('🗑️  Cleared existing incidents and blacklist entries.');

  // ── Sample Incident Documents ──────────────────────────────────────────────
  // Each document matches the Incident schema fields exactly:
  // incidentId, targetDomain, dangerLevel, reporterEmail, status, timestamp
  const incidents = [
    {
      incidentId:    'INC-1001',
      targetDomain:  defangHostname('secure-paypal-login.com'),
      dangerLevel:   'high',
      reporterEmail: 'analyst1@security.example',
      status:        'open',
      timestamp:     now,
    },
    {
      incidentId:    'INC-1002',
      targetDomain:  defangHostname('appleid.verify-account.org'),
      dangerLevel:   'medium',
      reporterEmail: 'analyst2@security.example',
      status:        'investigating',
      timestamp:     now,
    },
    {
      incidentId:    'INC-1003',
      targetDomain:  defangHostname('office365-login-secure.net'),
      dangerLevel:   'high',
      reporterEmail: 'threat@company.local',
      status:        'open',
      timestamp:     now,
    },
    {
      incidentId:    'INC-1004',
      targetDomain:  defangHostname('bank-update-verify.com'),
      dangerLevel:   'high',
      reporterEmail: 'fraud-team@bank.example',
      status:        'open',
      timestamp:     now,
    },
    {
      incidentId:    'INC-1005',
      targetDomain:  defangHostname('invoice-attachment-payments.biz'),
      dangerLevel:   'medium',
      reporterEmail: 'alerts@finance.example',
      status:        'closed',
      timestamp:     now,
    },
  ];

  await Incident.insertMany(incidents);
  console.log(`✅ Seeded ${incidents.length} incident(s).`);

  // ── Sample Blacklist Documents ─────────────────────────────────────────────
  // Each document matches the Blacklist schema fields exactly:
  // domainHash, originalDomain, addedAt
  const rawDomains = [
    'secure-paypal-login.com',
    'appleid.verify-account.org',
    'office365-login-secure.net',
    'bank-update-verify.com',
    'invoice-attachment-payments.biz',
  ];

  const blacklistDocs = rawDomains.map((d) => {
    const normalized = normalizeDomain(d);
    return {
      domainHash:     hashDomain(normalized),
      originalDomain: defangHostname(normalized),
      addedAt:        now,
    };
  });

  await Blacklist.insertMany(blacklistDocs);
  console.log(`✅ Seeded ${blacklistDocs.length} blacklist entry/entries.`);

  return { incidentsSeeded: incidents.length, blacklistSeeded: blacklistDocs.length };
}

module.exports = { seedSampleData };

// ── Run directly ───────────────────────────────────────────────────────────────
if (require.main === module) {
  seedSampleData()
    .then(async (res) => {
      console.log('🎉 Seeding complete:', res);
      await closeDB();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('💥 Seeding failed:', err.message);
      await closeDB();
      process.exitCode = 1;
    });
}
