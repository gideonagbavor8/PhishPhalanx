/* jslint es6:true, node:true */
'use strict';

const crypto   = require('crypto');
const mongoose = require('mongoose');

// ── Mongoose Schema ────────────────────────────────────────────────────────────

const blacklistSchema = new mongoose.Schema(
  {
    // SHA-256 hash of the normalized domain used as the unique identifier
    _id:           { type: String },
    target_domain: { type: String, required: true },
    malware_type:  { type: String, default: 'unknown' },
    date_added:    { type: Date,   default: Date.now },
  },
  {
    collection: 'blacklists',
    // Disable auto _id since we manage it manually (SHA-256 hash)
    _id: false,
  }
);

const Blacklist =
  mongoose.models.Blacklist || mongoose.model('Blacklist', blacklistSchema);

// ── Helper Functions ───────────────────────────────────────────────────────────

/**
 * Normalize a raw domain or defanged URL to a clean hostname.
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
 * Defang a hostname so it cannot be accidentally clicked or executed.
 * @param {string} input
 * @returns {string}
 */
function defangHostname(input) {
  if (!input) return '';
  let value = String(input).trim();
  value = value.replace(/^https?:\/\//i, (match) =>
    match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'
  );
  value = value.replace(/\./g, '[.]');
  return value;
}

/**
 * Compute the SHA-256 hash of a normalized domain value.
 * @param {string} value
 * @returns {string}
 */
function hashDomain(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

// ── Domain Operations ──────────────────────────────────────────────────────────

/**
 * Look up a normalized domain in MongoDB by its SHA-256 hash.
 * @param {string} domain
 * @returns {Promise<{ blacklisted: boolean, document: Object|null }>}
 */
async function checkBlacklist(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return { blacklisted: false, document: null };

  const docId = hashDomain(normalized);
  const doc   = await Blacklist.findById(docId).lean();
  return { blacklisted: !!doc, document: doc };
}

/**
 * Add a domain to the MongoDB blacklist (upsert — safe to call multiple times).
 * @param {string} domain
 * @param {string} [malwareType='unknown']
 * @returns {Promise<Object>}
 */
async function addToBlacklist(domain, malwareType = 'unknown') {
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain provided.');

  const defanged = defangHostname(normalized);
  const docId    = hashDomain(normalized);

  await Blacklist.findByIdAndUpdate(
    docId,
    {
      _id:           docId,
      target_domain: defanged,
      malware_type:  malwareType,
      date_added:    new Date(),
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  return { _id: docId, target_domain: defanged, malware_type: malwareType };
}

/**
 * Remove a domain from the blacklist collection.
 * @param {string} domain
 * @returns {Promise<boolean>}
 */
async function removeBlacklistEntry(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain provided.');

  const docId = hashDomain(normalized);
  await Blacklist.findByIdAndDelete(docId);
  return true;
}

module.exports = {
  Blacklist,
  normalizeDomain,
  defangHostname,
  hashDomain,
  checkBlacklist,
  addToBlacklist,
  removeBlacklistEntry,
};
