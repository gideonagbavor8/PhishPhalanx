/* jslint es6:true, node:true */
'use strict';

/**
 * models/Incident.js — Mongoose Schema & Model for Phishing Incidents
 * ─────────────────────────────────────────────────────────────────────────────
 * Defines the shape of every incident document stored in the MongoDB Atlas
 * "incidents" collection. Mongoose validates each document against this schema
 * before any write reaches the database, ensuring data integrity across the app.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const crypto   = require('crypto');
const mongoose = require('mongoose');

/**
 * incidentSchema
 * ─────────────────────────────────────────────────────────────────────────────
 * Fields:
 *  - incidentId    : Unique, auto-generated incident reference (e.g. INC-A1B2C3D4)
 *  - targetDomain  : The phishing/malicious domain being reported (required)
 *  - dangerLevel   : Severity of the threat — restricted to low/medium/high
 *  - reporterEmail : Email address of the analyst or automated reporter
 *  - status        : Workflow state — open (default) → investigating → closed
 *  - timestamp     : When the incident was first recorded (defaults to now)
 */
const incidentSchema = new mongoose.Schema(
  {
    // Unique incident reference ID — auto-generated using 4 random bytes
    // encoded as uppercase hex, e.g. "INC-3F9A12BC"
    incidentId: {
      type:     String,
      unique:   true,
      default:  () => `INC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    },

    // The domain or URL being reported as a phishing/malicious indicator.
    // Marked required so every incident has a traceable target.
    targetDomain: {
      type:     String,
      required: [true, 'targetDomain is required — every incident must have a target.'],
      trim:     true,
    },

    // Severity classification of the reported threat.
    // Restricted to three tiers; defaults to 'low' if not supplied.
    dangerLevel: {
      type:    String,
      enum:    {
        values:  ['low', 'medium', 'high'],
        message: 'dangerLevel must be one of: low, medium, high',
      },
      default: 'low',
    },

    // Email address of the analyst or automated system that filed this report.
    // Optional — some automated reporters may not have an associated email.
    reporterEmail: {
      type:  String,
      trim:  true,
    },

    // Workflow status of the incident investigation.
    // - open         : Newly filed, not yet assigned
    // - investigating : Being actively reviewed by an analyst
    // - closed       : Investigation complete, threat mitigated or dismissed
    status: {
      type:    String,
      enum:    {
        values:  ['open', 'investigating', 'closed'],
        message: 'status must be one of: open, investigating, closed',
      },
      default: 'open',
    },

    // The date and time the incident was recorded.
    // Defaults to the moment the document is created.
    timestamp: {
      type:    Date,
      default: Date.now,
    },
  },
  {
    // Explicitly name the MongoDB collection so it is always "incidents"
    // regardless of Mongoose's pluralisation rules.
    collection: 'incidents',
  }
);

/**
 * Export the Mongoose model.
 *
 * The guard `mongoose.models.Incident ||` prevents Mongoose from throwing an
 * OverwriteModelError when this file is required multiple times (e.g. in tests
 * or when hot-reloading). If the model already exists, the cached version is
 * returned; otherwise a new model is compiled from the schema.
 */
const Incident = mongoose.models.Incident || mongoose.model('Incident', incidentSchema);

module.exports = Incident;
