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
 * so that different representations of the same domain produce identical hashes.
 *
 * Normalization steps:
 *  1. Convert to lowercase and trim whitespace
 *  2. Replace defanged protocols (hxxp/hxxps) with http for parsing
 *  3. Remove actual protocols (http/https)
 *  4. Remove defanging brackets around dots ([.] → .)
 *  5. Extract only the hostname, discard any path
 *
 * Examples:
 *  - Input: "hxxps://evil[.]com/login"     → Output: "evil.com"
 *  - Input: "https://EVIL.COM/path?q=1"    → Output: "evil.com"
 *  - Input: "evil.com"                     → Output: "evil.com"
 *  - Input: "HTTP://EVIL[.]COM"            → Output: "evil.com"
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
 * Why defang? Prevents accidental clicks or execution:
 *  - A defanged string cannot be used as a real URL
 *  - Cannot be accidentally pasted into a browser
 *  - Safe to display in logs, reports, terminals
 *
 * Examples:
 *  - Input: "http://evil.com/login"      → Output: "hxxp://evil[.]com/login"
 *  - Input: "https://paypal.evil.com"    → Output: "hxxps://paypal[.]evil[.]com"
 *  - Input: "evil.com"                   → Output: "evil[.]com"
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
 * Why SHA-256?
 *  - Cryptographically secure one-way hash (cannot reverse)
 *  - Deterministic: same input always produces same output
 *  - Fast and collision-resistant (practical impossibility of duplicates)
 *  - Used as the unique indexed lookup key in MongoDB (domainHash field)
 *  - 64-character hex string is compact and indexable
 *
 * Example:
 *  - Input: "evil.com"  → Output: "abc123def456... (64-char hex string)"
 *  - Same input always produces the exact same hash
 *  - Different inputs virtually never produce the same hash
 *
 * @param {string} value  A normalized domain string (lowercase hostname only)
 * @returns {string}      64-character lowercase hexadecimal SHA-256 digest
 */
function hashDomain(value) {
  // Use Node.js crypto module to generate SHA-256 hash
  // .update(value, 'utf8') processes the string as UTF-8 bytes
  // .digest('hex') returns the hash as a lowercase hex string
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

// ── Blacklist Operations ───────────────────────────────────────────────────────

/**
 * checkBlacklist()
 * Checks whether a given domain appears in the MongoDB blacklist.
 *
 * Process:
 *  1. Normalizes the input domain (strips protocols, brackets, paths)
 *  2. Hashes the normalized domain using SHA-256
 *  3. Performs indexed O(1) lookup on the domainHash field in MongoDB
 *  4. Returns result object with blacklisted boolean and matching document
 *
 * @param {string} domain  Raw, defanged, or partial domain/URL to check
 *                         Examples: "evil.com", "hxxp://evil[.]com", "https://evil.com/path"
 * @returns {Promise<{ blacklisted: boolean, document: Object|null }>}
 *          - blacklisted: true if domain found in blacklist collection
 *          - document: full blacklist entry if found, null otherwise
 * @throws {Error} If database query fails
 */
async function checkBlacklist(domain) {
  try {
    // Step 1: Normalize the domain to canonical form (e.g., "evil.com")
    // This ensures "hxxps://evil[.]com/path" and "evil.com" match the same hash
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      console.warn('⚠️  Empty or invalid domain provided to checkBlacklist.');
      return { blacklisted: false, document: null };
    }

    // Step 2: Generate SHA-256 hash of the normalized domain
    const hash = hashDomain(normalized);

    // Step 3: Query MongoDB by domainHash field (indexed, unique) for fast O(1) lookup
    // Using .lean() returns plain JS objects instead of Mongoose documents (faster)
    const doc = await Blacklist.findOne({ domainHash: hash }).lean();

    // Step 4: Return result with boolean flag and document reference
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
 * Process:
 *  1. Normalizes the input domain (removes protocols, brackets, paths)
 *  2. Generates SHA-256 hash of the normalized domain for unique storage
 *  3. Defangs the domain (converts hxxp://evil[.]com format) for safe display
 *  4. Upserts the document to MongoDB (insert if new, update if already exists)
 *  5. Returns the resulting blacklist entry document
 *
 * Idempotent Design: Safe to call multiple times with the same domain
 * — subsequent calls will update the addedAt timestamp without creating duplicates.
 *
 * @param {string} domain       Raw or defanged domain/URL to blacklist
 *                              Examples: "evil.com", "https://evil.com/login", "hxxp://evil[.]com"
 * @returns {Promise<Object>}   The saved/updated blacklist document with fields:
 *                              - domainHash: SHA-256 hex string (64 chars)
 *                              - originalDomain: defanged format (e.g., "hxxp://evil[.]com")
 *                              - addedAt: timestamp when entry was added/updated
 * @throws {Error} If domain is invalid or database operation fails
 */
async function addToBlacklist(domain) {
  try {
    // Step 1: Normalize the raw input to canonical form
    // Example: "hxxps://evil[.]com/login" → "evil.com"
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      throw new Error('Invalid domain provided. Domain cannot be empty after normalization.');
    }

    // Step 2: Generate SHA-256 hash of the normalized domain
    // This serves as the unique, indexed lookup key in MongoDB
    // Example: "evil.com" → "abc123def456..." (64-character hex string)
    const hash = hashDomain(normalized);

    // Step 3: Defang the domain for safe storage and display
    // Converts dots to [.] and http to hxxp to prevent accidental execution
    // Example: "evil.com" → "evil[.]com"
    const defanged = defangHostname(normalized);

    // Step 4: Upsert the document using findOneAndUpdate
    // - If domainHash exists: update the addedAt timestamp
    // - If domainHash is new: insert a fresh document
    // This ensures no duplicate entries by the same hash
    const doc = await Blacklist.findOneAndUpdate(
      { domainHash: hash },
      {
        domainHash:     hash,
        originalDomain: defanged,
        addedAt:        new Date(),
      },
      {
        upsert: true,                    // Create if doesn't exist
        new: true,                       // Return updated document
        setDefaultsOnInsert: true,       // Apply schema defaults on insert
      }
    );

    // Step 5: Convert Mongoose document to plain JS object and return
    console.log(`✅ Domain added to blacklist: ${defanged} (hash: ${hash.substring(0, 8)}...)`);
    return doc.toObject();
  } catch (error) {
    console.error('❌ Failed to add domain to blacklist:', error.message);
    throw error;
  }
}

/**
 * removeBlacklistEntry()
 * Permanently removes a domain from the blacklist collection.
 *
 * Process:
 *  1. Normalizes the domain to canonical form
 *  2. Hashes the normalized domain
 *  3. Deletes the MongoDB document with matching domainHash
 *
 * @param {string} domain  Raw or defanged domain to remove
 *                         Examples: "evil.com", "hxxp://evil[.]com"
 * @returns {Promise<boolean>} Always returns true (idempotent)
 * @throws {Error} If domain is invalid or database operation fails
 */
async function removeBlacklistEntry(domain) {
  try {
    // Step 1: Normalize domain to canonical form
    const normalized = normalizeDomain(domain);
    if (!normalized) {
      throw new Error('Invalid domain provided. Domain cannot be empty after normalization.');
    }

    // Step 2: Generate SHA-256 hash of the normalized domain
    const hash = hashDomain(normalized);

    // Step 3: Delete the MongoDB document with matching domainHash
    const result = await Blacklist.deleteOne({ domainHash: hash });

    if (result.deletedCount === 0) {
      console.warn(`⚠️  Domain not found in blacklist (nothing deleted): ${normalized}`);
    } else {
      console.log(`✅ Removed domain from blacklist: ${normalized}`);
    }

    // Always return true (idempotent design — safe to call even if domain wasn't in list)
    return true;
  } catch (error) {
    console.error('❌ Failed to remove blacklist entry:', error.message);
    throw error;
  }
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
