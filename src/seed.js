/* jslint es6:true, node:true */
require('dotenv').config();
const crypto = require('crypto');
const { firestore } = require('../src/db');

/**
 * Defang a hostname or URL so it can be stored safely in Firestore.
 * @param {string} domain
 * @returns {string}
 */
function defangDomain(domain) {
  if (!domain) return '';
  let v = String(domain).trim();
  v = v.replace(/^https?:\/\//i, (m) => (m.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'));
  v = v.replace(/\./g, '[.]');
  return v;
}

/**
 * Create a SHA-256 hash for a normalized domain value.
 * @param {string} domain
 * @returns {string}
 */
function hashDomain(domain) {
  return crypto.createHash('sha256').update(domain, 'utf8').digest('hex');
}

/**
 * Seed sample phishing incident and blacklist documents into Firestore.
 * @returns {Promise<{incidentsSeeded:number, blacklistSeeded:number}>}
 */
async function seedSampleData() {
  const now = firestore.Timestamp ? firestore.Timestamp.now() : new Date();

  // Sample incidents (realistic phishing examples)
  const incidents = [
    {
      incidentId: 'inc-1001',
      targetDomain: defangDomain('secure-paypal-login.com'),
      dangerLevel: 'high',
      reporterEmail: 'analyst1@security.example',
      status: 'open',
      timestamp: now,
    },
    {
      incidentId: 'inc-1002',
      targetDomain: defangDomain('appleid.verify-account.org'),
      dangerLevel: 'medium',
      reporterEmail: 'analyst2@security.example',
      status: 'investigating',
      timestamp: now,
    },
    {
      incidentId: 'inc-1003',
      targetDomain: defangDomain('office365-login-secure.net'),
      dangerLevel: 'high',
      reporterEmail: 'threat@company.local',
      status: 'open',
      timestamp: now,
    },
    {
      incidentId: 'inc-1004',
      targetDomain: defangDomain('bank-update-verify.com'),
      dangerLevel: 'critical',
      reporterEmail: 'fraud-team@bank.example',
      status: 'open',
      timestamp: now,
    },
    {
      incidentId: 'inc-1005',
      targetDomain: defangDomain('invoice-attachment-payments.biz'),
      dangerLevel: 'medium',
      reporterEmail: 'alerts@finance.example',
      status: 'closed',
      timestamp: now,
    },
  ];

  // Sample blacklist entries
  const blacklist = [
    'secure-paypal-login.com',
    'appleid.verify-account.org',
    'office365-login-secure.net',
    'bank-update-verify.com',
    'invoice-attachment-payments.biz',
  ];

  const batch = firestore.batch();

  // Write incidents
  incidents.forEach((inc) => {
    const docRef = firestore.collection('incidents').doc(inc.incidentId);
    batch.set(docRef, {
      incidentId: inc.incidentId,
      targetDomain: inc.targetDomain,
      dangerLevel: inc.dangerLevel,
      reporterEmail: inc.reporterEmail,
      status: inc.status,
      timestamp: inc.timestamp,
    });
  });

  // Write blacklist entries to the standard `blacklists` collection.
  blacklist.forEach((d) => {
    const normalized = String(d).trim().toLowerCase();
    const docId = hashDomain(normalized);
    const docRef = firestore.collection('blacklists').doc(docId);
    batch.set(docRef, {
      domainHash: docId,
      originalDomain: defangDomain(normalized),
      addedAt: now,
    });
  });

  await batch.commit();
  return { incidentsSeeded: incidents.length, blacklistSeeded: blacklist.length };
}

module.exports = { seedSampleData };

if (require.main === module) {
  seedSampleData()
    .then((res) => {
      console.log('Seeding complete', res);
      process.exit(0);
    })
    .catch((err) => {
      console.error('Seeding failed:', err);
      process.exitCode = 1;
    });
}

