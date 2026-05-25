/* jslint es6:true, node:true */
const crypto = require('crypto');
const { getFirebase } = require('./db');

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
 * Look up a normalized domain in Firestore by its SHA-256 hash.
 * Returns whether the item is blacklisted and the matching document.
 */
async function checkBlacklist(domain, options = {}) {
  const { firestore } = getFirebase(options);
  const normalized = normalizeDomain(domain);
  if (!normalized) {
    return { blacklisted: false, document: null };
  }

  const docId = hashDomain(normalized);
  const doc = await firestore.collection(BLACKLIST_COLLECTION).doc(docId).get();
  return {
    blacklisted: doc.exists,
    document: doc.exists ? Object.assign({ id: doc.id }, doc.data()) : null,
  };
}

/**
 * Add a domain to Firestore blacklist storage after defanging and hashing it.
 * @param {string} domain
 * @returns {Promise<Object>}
 */
async function addToBlacklist(domain, options = {}) {
  const { firestore } = getFirebase(options);
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain');

  const defanged = defangHostname(normalized);
  const docId = hashDomain(normalized);
  const now = firestore.Timestamp ? firestore.Timestamp.now() : new Date();

  await firestore.collection(BLACKLIST_COLLECTION).doc(docId).set({
    domainHash: docId,
    originalDomain: defanged,
    addedAt: now,
  }, { merge: false });

  return {
    domainHash: docId,
    originalDomain: defanged,
    addedAt: now,
  };
}

/**
 * Remove a domain from the blacklist collection.
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
async function removeBlacklistEntry(domain, options = {}) {
  const { firestore } = getFirebase(options);
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain');
  const docId = hashDomain(normalized);
  await firestore.collection(BLACKLIST_COLLECTION).doc(docId).delete();
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
