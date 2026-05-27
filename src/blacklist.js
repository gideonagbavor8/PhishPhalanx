/* jslint es6:true, node:true */
const crypto = require('crypto');
const { getDb } = require('./db');

const BLACKLIST_COLLECTION = 'blacklists';

/**
 * Normalize a raw domain or defanged URL to a clean hostname for hashing.
 * @param {string} rawDomain
 * @returns {string}
 */
function normalizeDomain(rawDomain) {
  if (!rawDomain) return '';
  let value = String(rawDomain).trim().toLowerCase();
  value = value.replace(/^hxxps?:\/\//, 'http://');
  value = value.replace(/^https?:\/\//, '');
  value = value.replace(/\[\.\]/g, '.');
  value = value.split('/')[0];
  return value;
}

/**
 * Defang a hostname or URL so it cannot be executed accidentally.
 * @param {string} input
 * @returns {string}
 */
function defangHostname(input) {
  if (!input) return '';
  let value = String(input).trim();
  value = value.replace(/^https?:\/\//i, (match) => {
    return match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://';
  });
  value = value.replace(/\./g, '[.]');
  return value;
}

/**
 * Compute the SHA-256 hash for a normalized domain value.
 * @param {string} value
 * @returns {string}
 */
function hashDomain(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Look up a normalized domain in MongoDB by its SHA-256 hash (_id).
 */
async function checkBlacklist(domain) {
  const db = await getDb();
  const normalized = normalizeDomain(domain);
  if (!normalized) {
    return { blacklisted: false, document: null };
  }

  const docId = hashDomain(normalized);
  const doc = await db.collection(BLACKLIST_COLLECTION).findOne({ _id: docId });
  return {
    blacklisted: !!doc,
    document: doc,
  };
}

/**
 * Add a domain to MongoDB blacklist storage.
 * @param {string} domain
 * @param {string} [malwareType='unknown']
 * @returns {Promise<Object>}
 */
async function addToBlacklist(domain, malwareType = 'unknown') {
  const db = await getDb();
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain');

  const defanged = defangHostname(normalized);
  const docId = hashDomain(normalized);
  const now = new Date();

  const doc = {
    _id: docId,
    target_domain: defanged,
    malware_type: malwareType,
    date_added: now,
  };

  await db.collection(BLACKLIST_COLLECTION).updateOne(
    { _id: docId },
    { $set: doc },
    { upsert: true }
  );

  return doc;
}

/**
 * Remove a domain from the blacklist collection.
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
async function removeBlacklistEntry(domain) {
  const db = await getDb();
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain');
  
  const docId = hashDomain(normalized);
  await db.collection(BLACKLIST_COLLECTION).deleteOne({ _id: docId });
  return true;
}

module.exports = {
  normalizeDomain,
  defangHostname,
  hashDomain,
  checkBlacklist,
  addToBlacklist,
  removeBlacklistEntry,
};
