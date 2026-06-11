/* jslint es6:true, node:true */
'use strict';

/**
 * blacklist.js — Domain Blacklist Lookup & Management
 * ─────────────────────────────────────────────────────────────────────────────
 * Provides the business logic for adding, removing, and checking domains
 * against the PhishPhalanx blacklist stored in MongoDB Atlas using the native
 * MongoDB Node.js driver instead of Mongoose.
 *
 * Key design decisions:
 *  - Domains are hashed with SHA-256 before storage → fast index lookups
 *  - Raw domains are "defanged" before storage → prevents accidental execution
 * ─────────────────────────────────────────────────────────────────────────────
 */

const crypto = require('crypto');
const db = require('./db');

// ── Helper / Utility Functions ─────────────────────────────────────────────────

/**
 * normalizeDomain()
 * Strips protocols, defanging brackets, and paths from a raw domain string
 * so that different representations of the same domain produce identical hashes.
 *
 * Normalization steps:
 *  1. Convert to lowercase and trim whitespace
 *  2. Replace defanged protocols (hxxp/hxxps) with http for parsing
 *  3. Remove actual protocols (http/https)
 *  4. Remove defanging brackets around dots ([.] → .)
 *  5. Extract only the hostname, discard any path
 *
 * @param {string} rawDomain  Any form of domain string (URL, defanged, etc.)
 * @returns {string}          Canonical lowercase hostname only
 */
function normalizeDomain(rawDomain) {
  if (!rawDomain) return '';
  let value = String(rawDomain).trim().toLowerCase();
  // Step 1: Convert defanged hxxp/hxxps back to http:// for URL parsing
  value = value.replace(/^hxxps?:\/\//, 'http://');
  // Step 2: Strip standard protocol prefix
  value = value.replace(/^https?:\/\//, '');
  // Step 3: Remove defanging brackets around dots: evil[.]com → evil.com
  value = value.replace(/\[\.\]/g, '.');
  // Step 4: Keep only the hostname, discard any path
  value = value.split('/')[0];
  return value;
}

/**
 * defangHostname()
 * Renders a domain or URL safe for display in reports and terminals by
 * replacing dangerous characters with safe equivalents per MITRE ATT&CK convention.
 *
 * Defanging process:
 *  1. Convert http:// → hxxp:// and https:// → hxxps://
 *  2. Replace all dots (.) with [.]
 *
 * @param {string} input   Raw domain, URL, or hostname to defang
 * @returns {string}       Defanged string safe for display and reporting
 */
function defangHostname(input) {
  if (!input) return '';
  let value = String(input).trim();
  // Step 1: Convert protocols to defanged equivalents
  value = value.replace(
    /^https?:\/\//i,
    (match) => match.toLowerCase().startsWith('https') ? 'hxxps://' : 'hxxp://'
  );
  // Step 2: Replace all dots with brackets to prevent accidental execution
  value = value.replace(/\./g, '[.]');
  return value;
}

/**
 * hashDomain()
 * Produces a deterministic SHA-256 hex digest for a normalized domain string.
 *
 * @param {string} value  A normalized domain string (lowercase hostname only)
 * @returns {string}      64-character lowercase hexadecimal SHA-256 digest
 */
function hashDomain(value) {
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

// ── Blacklist Operations ───────────────────────────────────────────────────────

/**
 * checkBlacklist()
 * Checks whether a given domain appears in the MongoDB blacklist.
 *
 * @param {string} domain  Raw, defanged, or partial domain/URL to check
 * @returns {Promise<{ blacklisted: boolean, document: Object|null }>}
 * @throws {Error} If database query fails
 */
async function checkBlacklist(domain) {
  try {
    // Step 1: Normalize domain to lowercase canonical hostname
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      console.warn('⚠️  Empty or invalid domain provided to checkBlacklist.');
      return { blacklisted: false, document: null };
    }

    // Step 2: Generate unique SHA-256 hash
    const hash = hashDomain(normalized);

    // Step 3: Query MongoDB collection using the driver's findOne() method.
    // The MongoDB driver's collection('blacklist').findOne(query) method finds and returns the
    // first document in the collection matching the query filter. In this case, we query by
    // domainHash which performs an exact hash match. If no document matches, it returns null.
    const doc = await db.collection('blacklist').findOne({ domainHash: hash });

    const result = {
      blacklisted: !!doc,
      document: doc,
    };

    if (doc) {
      console.log(`✅ Domain found in blacklist: ${doc.originalDomain}`);
    } else {
      console.log(`ℹ️  Domain not found in blacklist: ${normalized}`);
    }

    return result;
  } catch (error) {
    console.error('❌ Failed to check blacklist:', error.message);
    throw error;
  }
}

/**
 * addToBlacklist()
 * Adds a domain to the MongoDB blacklist with SHA-256 hashing and defanging.
 *
 * @param {string} domain       Raw or defanged domain/URL to blacklist
 * @returns {Promise<Object>}   The saved blacklist document
 * @throws {Error} If domain is invalid or database operation fails
 */
async function addToBlacklist(domain) {
  try {
    // Step 1: Normalize input to canonical hostname
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      throw new Error('Invalid domain provided. Domain cannot be empty after normalization.');
    }

    // Step 2: Hash normalized domain
    const hash = hashDomain(normalized);
    // Step 3: Defang for safety
    const defanged = defangHostname(normalized);

    // Step 4: Check if the domain is already blacklisted to prevent duplicates
    // directly before attempting insertion.
    const existing = await db.collection('blacklist').findOne({ domainHash: hash });
    if (existing) {
      console.log(`ℹ️  Domain is already blacklisted: ${defanged}. Returning existing record.`);
      return existing;
    }

    const doc = {
      domainHash: hash,
      originalDomain: defanged,
      addedAt: new Date(),
    };

    // Step 5: Insert document into MongoDB collection using the driver's insertOne() method.
    // The MongoDB driver's collection('blacklist').insertOne() method inserts a single
    // document into the collection. It modifies the document object in-place by adding
    // a unique '_id' field before sending it to Atlas.
    await db.collection('blacklist').insertOne(doc);
    console.log(`✅ Domain added to blacklist: ${defanged} (hash: ${hash.substring(0, 8)}...)`);
    return doc;
  } catch (error) {
    console.error('❌ Failed to add domain to blacklist:', error.message);
    throw error;
  }
}

/**
 * removeBlacklistEntry()
 * Permanently removes a domain from the blacklist collection.
 *
 * @param {string} domain  Raw or defanged domain to remove
 * @returns {Promise<boolean>} Always returns true (idempotent)
 * @throws {Error} If domain is invalid or database operation fails
 */
async function removeBlacklistEntry(domain) {
  try {
    // Step 1: Normalize domain to canonical hostname
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      throw new Error('Invalid domain provided. Domain cannot be empty after normalization.');
    }

    // Step 2: Hash normalized domain
    const hash = hashDomain(normalized);

    // Step 3: Delete document using the driver's deleteOne() method.
    // The MongoDB driver's collection('blacklist').deleteOne(filter) method deletes a single
    // document matching the query filter. It returns an object containing deletedCount.
    const result = await db.collection('blacklist').deleteOne({ domainHash: hash });

    if (result.deletedCount === 0) {
      console.warn(`⚠️  Domain not found in blacklist (nothing deleted): ${normalized}`);
    } else {
      console.log(`✅ Removed domain from blacklist: ${normalized}`);
    }

    return true;
  } catch (error) {
    console.error('❌ Failed to remove blacklist entry:', error.message);
    throw error;
  }
}

module.exports = {
  normalizeDomain,
  defangHostname,
  hashDomain,
  checkBlacklist,
  addToBlacklist,
  removeBlacklistEntry,
};
