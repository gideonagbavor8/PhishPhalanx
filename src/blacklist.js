/* jslint es6:true, node:true */
'use strict';

/**
 * blacklist.js — Domain Blacklist Lookup & Management
 * ─────────────────────────────────────────────────────────────────────────────
 * Provides the business logic for adding, removing, and checking domains
 * against the PhishPhalanx blacklist stored in MongoDB Atlas.
 *
 * The Blacklist Mongoose model (schema, validation) lives in:
 *   /src/models/Blacklist.js
 *
 * Key design decisions:
 *  - Domains are hashed with SHA-256 before storage → fast index lookups
 *  - Raw domains are "defanged" before storage → prevents accidental execution
 * ─────────────────────────────────────────────────────────────────────────────
 */

const crypto    = require('crypto');

// Import the Blacklist model from the dedicated models folder.
const Blacklist = require('./models/Blacklist');

// ── Helper / Utility Functions ─────────────────────────────────────────────────

/**
 * normalizeDomain()
 * Strips protocols, defanging brackets, and paths from a raw domain string
 * so that "hxxps://evil[.]com/login" and "evil.com" produce the same hash.
 *
 * @param {string} rawDomain
 * @returns {string} Clean, lowercase hostname only
 */
function normalizeDomain(rawDomain) {
  if (!rawDomain) return '';
  let value = String(rawDomain).trim().toLowerCase();
  // Convert defanged hxxp/hxxps back to a parseable form
  value = value.replace(/^hxxps?:\/\//, 'http://');
  // Strip protocol prefix
  value = value.replace(/^https?:\/\//, '');
  // Remove defanging brackets around dots: evil[.]com → evil.com
  value = value.replace(/\[\.\]/g, '.');
  // Keep only the hostname, strip any path
  value = value.split('/')[0];
  return value;
}

/**
 * defangHostname()
 * Renders a domain or URL safe for display in reports and terminals by
 * replacing dots with [.] and http with hxxp — the MITRE ATT&CK convention.
 *
 * @param {string} input
 * @returns {string} Defanged string safe for display
 */
function defangHostname(input) {
  if (!input) return '';
  let value = String(input).trim();
  value = value.replace(
    /^https?:\/\//i,
    (match) => match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'
  );
  value = value.replace(/\./g, '[.]');
  return value;
}

/**
 * hashDomain()
 * Produces a deterministic SHA-256 hex digest for a normalised domain.
 * This hash is used as the unique lookup key (domainHash field) in MongoDB.
 *
 * @param {string} value  A normalised domain string
 * @returns {string}      64-character lowercase hex string
 */
function hashDomain(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

// ── Blacklist Operations ───────────────────────────────────────────────────────

/**
 * checkBlacklist()
 * Checks whether a given domain appears in the MongoDB blacklist.
 * Normalises the input and queries by domainHash for an indexed O(1) lookup.
 *
 * @param {string} domain  Raw or defanged domain/URL to check
 * @returns {Promise<{ blacklisted: boolean, document: Object|null }>}
 */
async function checkBlacklist(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) return { blacklisted: false, document: null };

  const hash = hashDomain(normalized);
  // Query by the domainHash field (indexed, unique) for fast lookup
  const doc  = await Blacklist.findOne({ domainHash: hash }).lean();
  return { blacklisted: !!doc, document: doc };
}

/**
 * addToBlacklist()
 * Adds a domain to the MongoDB blacklist using an upsert — safe to call
 * repeatedly with the same domain without creating duplicates.
 *
 * @param {string} domain       Raw or defanged domain to blacklist
 * @returns {Promise<Object>}   The resulting blacklist document
 */
async function addToBlacklist(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain provided.');

  const hash     = hashDomain(normalized);
  const defanged = defangHostname(normalized);

  // findOneAndUpdate with upsert: insert if not found, update if already exists
  const doc = await Blacklist.findOneAndUpdate(
    { domainHash: hash },
    {
      domainHash:     hash,
      originalDomain: defanged,
      addedAt:        new Date(),
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  return doc.toObject();
}

/**
 * removeBlacklistEntry()
 * Permanently removes a domain from the blacklist collection.
 *
 * @param {string} domain  Raw or defanged domain to remove
 * @returns {Promise<boolean>} true if the operation completed
 */
async function removeBlacklistEntry(domain) {
  const normalized = normalizeDomain(domain);
  if (!normalized) throw new Error('Invalid domain provided.');

  const hash = hashDomain(normalized);
  await Blacklist.deleteOne({ domainHash: hash });
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
