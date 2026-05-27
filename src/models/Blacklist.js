/* jslint es6:true, node:true */
'use strict';

/**
 * models/Blacklist.js — Mongoose Schema & Model for Blacklisted Domains
 * ─────────────────────────────────────────────────────────────────────────────
 * Defines the shape of every blacklist document stored in the MongoDB Atlas
 * "blacklists" collection. Each entry represents a confirmed malicious domain
 * identified by its SHA-256 hash (collision-resistant, index-friendly) with
 * the original domain stored in defanged form to prevent accidental execution.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const mongoose = require('mongoose');

/**
 * blacklistSchema
 * ─────────────────────────────────────────────────────────────────────────────
 * Fields:
 *  - domainHash     : SHA-256 hex hash of the normalised domain (unique key)
 *  - originalDomain : Defanged representation of the domain (e.g. evil[.]com)
 *  - addedAt        : Timestamp when this domain was added to the blacklist
 */
const blacklistSchema = new mongoose.Schema(
  {
    // SHA-256 hex digest of the normalised domain string.
    // Used as the primary lookup key — hashing allows fast indexed lookups
    // and avoids storing raw credentials / sensitive domain strings as IDs.
    // Marked unique so the same domain cannot be added twice.
    domainHash: {
      type:     String,
      required: [true, 'domainHash is required — every blacklist entry needs a SHA-256 hash.'],
      unique:   true,
      trim:     true,
    },

    // The defanged representation of the original domain or URL.
    // "Defanging" replaces dots with [.] and http with hxxp so the value
    // cannot be accidentally clicked or executed in a terminal/browser.
    // Example: "evil.com" → "evil[.]com"
    originalDomain: {
      type:  String,
      trim:  true,
    },

    // The date and time this domain was added to the blacklist.
    // Defaults to the moment the document is inserted.
    addedAt: {
      type:    Date,
      default: Date.now,
    },
  },
  {
    // Explicitly name the MongoDB collection.
    collection: 'blacklists',
  }
);

/**
 * Export the Mongoose model.
 *
 * The guard `mongoose.models.Blacklist ||` prevents an OverwriteModelError
 * if this module is required more than once during the same process lifetime.
 */
const Blacklist = mongoose.models.Blacklist || mongoose.model('Blacklist', blacklistSchema);

module.exports = Blacklist;
