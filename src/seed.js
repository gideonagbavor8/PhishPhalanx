/* jslint es6:true, node:true */
'use strict';

/**
 * seed.js — Database Seeder for PhishPhalanx
 * ─────────────────────────────────────────────────────────────────────────────
 * Populates MongoDB Atlas with sample phishing incidents and blacklisted
 * domains for development, testing, and demonstration purposes using the native
 * MongoDB Node.js driver.
 *
 * Run directly: node src/seed.js
 * Or via npm  : npm run seed
 * ─────────────────────────────────────────────────────────────────────────────
 */

require('dotenv').config();
const db                                              = require('./db');
const { defangHostname, hashDomain, normalizeDomain } = require('./blacklist');

/**
 * seedSampleData()
 * Clears existing incidents and blacklist entries, then inserts fresh sample
 * data. Designed to be idempotent — safe to run multiple times.
 *
 * @returns {Promise<{ incidentsSeeded: number, blacklistSeeded: number }>}
 */
async function seedSampleData() {
  // Ensure we are connected to MongoDB Atlas.
  await db.connectDB();
  const now = new Date();

  // ── Clear existing data ────────────────────────────────────────────────────
  // The MongoDB driver's collection().deleteMany(filter) method deletes all documents
  // matching the filter query. An empty filter {} matches all documents in the collection,
  // effectively clearing the collection.
  await db.collection('incidents').deleteMany({});
  await db.collection('blacklist').deleteMany({});
  console.log('🗑️  Cleared existing incidents and blacklist entries.');

  // ── Sample Incident Documents ──────────────────────────────────────────────
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

  // The MongoDB driver's collection().insertMany(docs) method inserts an array of
  // documents into the collection. It modifies each document in-place to add a unique '_id' field.
  await db.collection('incidents').insertMany(incidents);
  console.log(`✅ Seeded ${incidents.length} incident(s).`);

  // ── Sample Blacklist Documents ─────────────────────────────────────────────
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

  // The MongoDB driver's collection().insertMany(docs) method inserts an array of
  // documents into the collection. It modifies each document in-place to add a unique '_id' field.
  await db.collection('blacklist').insertMany(blacklistDocs);
  console.log(`✅ Seeded ${blacklistDocs.length} blacklist entry/entries.`);

  return { incidentsSeeded: incidents.length, blacklistSeeded: blacklistDocs.length };
}

module.exports = { seedSampleData };

// ── Run directly ───────────────────────────────────────────────────────────────
if (require.main === module) {
  seedSampleData()
    .then(async (res) => {
      console.log('🎉 Seeding complete:', res);
      await db.closeDB();
      process.exit(0);
    })
    .catch(async (err) => {
      console.error('💥 Seeding failed:', err.message);
      await db.closeDB();
      process.exitCode = 1;
    });
}
