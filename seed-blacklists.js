/* jslint es6:true, node:true */
/**
 * Seed script for PhishPhalanx `blacklists` collection.
 * Each blacklist document ID is the SHA-256 hash of the normalized target domain.
 * The stored target_domain string is explicitly defanged before insertion.
 */
const crypto = require('crypto');
const admin = require('firebase-admin');
const { initializeFirebase } = require('./firebase-admin-init');

const BLACKLIST_COLLECTION = 'blacklists';

/**
 * Defang a hostname or URL to prevent accidental execution by analysts.
 * Examples:
 *   example.com -> example[.]com
 *   http://malicious.com -> hxxp://malicious[.]com
 * @param {string} input
 * @returns {string}
 */
function defangHostname(input) {
  if (!input || typeof input !== 'string') {
    return '';
  }

  let value = input.trim();

  // Replace protocol tokens first for URLs.
  value = value.replace(/^https?:\/\//i, (match) => {
    return match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://';
  });

  // Replace dots on hostnames/paths.
  value = value.replace(/\./g, '[.]');

  return value;
}

/**
 * Normalize a domain name for deterministic hashing.
 * Accepts raw or defanged hostnames, strips protocol and path segments,
 * and converts brackets back to literal dots.
 * @param {string} rawDomain
 * @returns {string}
 */
function normalizeDomain(rawDomain) {
  let value = String(rawDomain).trim().toLowerCase();
  value = value.replace(/^hxxps?:\/\//, 'http://');
  value = value.replace(/^https?:\/\//, '');
  value = value.replace(/\[\.\]/g, '.');
  value = value.split('/')[0];
  return value;
}

/**
 * Create a SHA-256 digest in hex format.
 * @param {string} value
 * @returns {string}
 */
function hashDomain(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Seed blacklist entries into Firestore.
 * @param {Array<{target_domain:string, malware_type:string}>} entries
 * @param {Object} options
 * @returns {Promise<void>}
 */
async function seedBlacklistEntries(entries, options = {}) {
  if (!Array.isArray(entries) || entries.length === 0) {
    throw new Error('No blacklist entries provided for seeding.');
  }

  const { firestore } = initializeFirebase(options);
  const batch = firestore.batch();
  const now = (admin && admin.firestore && admin.firestore.Timestamp)
    ? admin.firestore.Timestamp.now()
    : new Date();

  entries.forEach((entry) => {
    const normalizedDomain = normalizeDomain(entry.target_domain);
    if (!normalizedDomain) {
      throw new Error('Blacklist entry contains invalid target_domain.');
    }

    const docId = hashDomain(normalizedDomain);
    const docRef = firestore.collection(BLACKLIST_COLLECTION).doc(docId);

    batch.set(docRef, {
      target_domain: defangHostname(normalizedDomain),
      malware_type: String(entry.malware_type || 'unknown').trim(),
      date_added: now,
    }, { merge: false });
  });

  await batch.commit();
}

/**
 * Example seed dataset for the blacklist collection.
 */
const defaultBlacklistEntries = [
  {
    target_domain: 'phishing.example.com',
    malware_type: 'credential-harvest',
  },
  {
    target_domain: 'malicious-login.corp',
    malware_type: 'credential-harvest',
  },
  {
    target_domain: 'wire-transfer-fraud.net',
    malware_type: 'business-email-compromise',
  },
  {
    target_domain: 'updates-secure-payments.com',
    malware_type: 'fake-update',
  },
];

/**
 * Main script entrypoint for running the legacy blacklist seeder.
 */
async function main() {
  try {
    console.log('Initializing Firebase connection for PhishPhalanx seed script...');

    await seedBlacklistEntries(defaultBlacklistEntries, {
      projectId: 'phishphalanx-demo',
      storageBucket: 'phishphalanx-storage',
      useEmulator: true,
      emulatorHost: '127.0.0.1',
      emulatorFirestorePort: 8080,
      emulatorStoragePort: 9199,
    });

    console.log(`Seeded ${defaultBlacklistEntries.length} blacklist entries to Firestore.`);
  } catch (error) {
    console.error('Failed to seed blacklists:', error);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  defangHostname,
  normalizeDomain,
  hashDomain,
  seedBlacklistEntries,
};
