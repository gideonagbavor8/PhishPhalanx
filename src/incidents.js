/* jslint es6:true, node:true */
'use strict';

/**
 * incidents.js — CRUD Operations for Phishing Incidents
 * ─────────────────────────────────────────────────────────────────────────────
 * Provides the business logic layer for creating, reading, and updating
 * phishing incident records. All database interaction goes through the
 * Incident Mongoose model defined in /src/models/Incident.js.
 * ─────────────────────────────────────────────────────────────────────────────
 */

// Import the Incident model from the dedicated models folder.
// The schema (fields, validation, enums) lives there; this file only
// contains the functions that operate on those documents.
const Incident = require('./models/Incident');

// ── CRUD Operations ────────────────────────────────────────────────────────────

/**
 * createIncident()
 * Creates and persists a new phishing incident document in MongoDB Atlas.
 *
 * @param {{ reporterEmail?: string, dangerLevel?: string, targetDomain: string }} params
 * @returns {Promise<Object>} The saved incident as a plain JS object
 */
async function createIncident({ reporterEmail, dangerLevel, targetDomain } = {}) {
  const incident = new Incident({
    targetDomain:  targetDomain  || 'unknown',
    dangerLevel:   dangerLevel   || 'low',
    reporterEmail: reporterEmail || '',
    // incidentId, status, and timestamp use schema defaults automatically
  });

  await incident.save();
  return incident.toObject();
}

/**
 * listIncidents()
 * Retrieves incidents from MongoDB, with optional filtering.
 *
 * @param {{ status?: string, dangerLevel?: string }} filters
 * @returns {Promise<Array>} Array of incident documents (plain objects)
 */
async function listIncidents(filters = {}) {
  const query = {};
  if (filters.status)      query.status      = filters.status;
  if (filters.dangerLevel) query.dangerLevel  = filters.dangerLevel;

  // Sort newest first using the timestamp field defined in the schema
  return Incident.find(query).sort({ timestamp: -1 }).lean();
}

/**
 * updateIncidentStatus()
 * Updates the workflow status of a specific incident by its incidentId.
 *
 * Valid transitions: open → investigating → closed
 *
 * @param {string} incidentId  The unique INC-XXXXXXXX identifier
 * @param {string} newStatus   Must be one of: open, investigating, closed
 * @returns {Promise<boolean>} true if update succeeded
 * @throws {Error} If the status is invalid or the incident is not found
 */
async function updateIncidentStatus(incidentId, newStatus) {
  const validStatuses = ['open', 'investigating', 'closed'];
  if (!validStatuses.includes(newStatus)) {
    throw new Error(`Invalid status "${newStatus}". Must be one of: ${validStatuses.join(', ')}`);
  }

  const result = await Incident.updateOne(
    { incidentId },
    { $set: { status: newStatus } }
  );

  if (result.matchedCount === 0) {
    throw new Error(`Incident "${incidentId}" not found.`);
  }
  return true;
}

module.exports = {
  Incident,
  createIncident,
  listIncidents,
  updateIncidentStatus,
};
