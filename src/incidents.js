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
 * @throws {Error} If validation fails or database operation fails
 */
async function createIncident({ reporterEmail, dangerLevel, targetDomain } = {}) {
  try {
    const incident = new Incident({
      targetDomain:  targetDomain  || 'unknown',
      dangerLevel:   dangerLevel   || 'low',
      reporterEmail: reporterEmail || '',
      // incidentId, status, and timestamp use schema defaults automatically
    });

    await incident.save();
    console.log(`✅ Incident created successfully: ${incident.incidentId}`);
    return incident.toObject();
  } catch (error) {
    console.error('❌ Failed to create incident:', error.message);
    throw error;
  }
}

/**
 * listIncidents()
 * Retrieves incidents from MongoDB, with optional filtering.
 *
 * @param {{ status?: string, dangerLevel?: string }} filters
 * @returns {Promise<Array>} Array of incident documents (plain objects)
 * @throws {Error} If database query fails
 */
async function listIncidents(filters = {}) {
  try {
    const query = {};
    if (filters.status)      query.status      = filters.status;
    if (filters.dangerLevel) query.dangerLevel  = filters.dangerLevel;

    // Sort newest first using the timestamp field defined in the schema
    const incidents = await Incident.find(query).sort({ timestamp: -1 }).lean();
    console.log(`✅ Retrieved ${incidents.length} incident(s) with filters:`, filters);
    return incidents;
  } catch (error) {
    console.error('❌ Failed to list incidents:', error.message);
    throw error;
  }
}

/**
 * getIncident()
 * Finds a single incident by its unique incidentId.
 *
 * @param {string} incidentId  The unique INC-XXXXXXXX identifier
 * @returns {Promise<Object|null>} The incident document or null if not found
 * @throws {Error} If database query fails
 */
async function getIncident(incidentId) {
  try {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('Invalid incidentId provided. Must be a non-empty string.');
    }

    const incident = await Incident.findOne({ incidentId }).lean();
    
    if (!incident) {
      console.warn(`⚠️  Incident "${incidentId}" not found.`);
      return null;
    }

    console.log(`✅ Retrieved incident: ${incidentId}`);
    return incident;
  } catch (error) {
    console.error('❌ Failed to retrieve incident:', error.message);
    throw error;
  }
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
  try {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('Invalid incidentId provided. Must be a non-empty string.');
    }

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

    console.log(`✅ Updated incident ${incidentId} status to "${newStatus}"`);
    return true;
  } catch (error) {
    console.error('❌ Failed to update incident status:', error.message);
    throw error;
  }
}

/**
 * deleteIncident()
 * Removes a false positive or incorrectly flagged incident from the database.
 *
 * @param {string} incidentId  The unique INC-XXXXXXXX identifier
 * @returns {Promise<boolean>} true if deletion succeeded
 * @throws {Error} If the incident is not found or deletion fails
 */
async function deleteIncident(incidentId) {
  try {
    if (!incidentId || typeof incidentId !== 'string') {
      throw new Error('Invalid incidentId provided. Must be a non-empty string.');
    }

    const result = await Incident.deleteOne({ incidentId });

    if (result.deletedCount === 0) {
      throw new Error(`Incident "${incidentId}" not found. Nothing was deleted.`);
    }

    console.log(`✅ Deleted incident: ${incidentId}`);
    return true;
  } catch (error) {
    console.error('❌ Failed to delete incident:', error.message);
    throw error;
  }
}

/**
 * getIncidentsBySeverity()
 * Queries all OPEN incidents matching a specific danger level.
 *
 * @param {string} level  Must be one of: low, medium, high
 * @returns {Promise<Array>} Array of open incident documents sorted by newest first
 * @throws {Error} If the severity level is invalid or database query fails
 */
async function getIncidentsBySeverity(level) {
  try {
    const validLevels = ['low', 'medium', 'high'];
    if (!validLevels.includes(level)) {
      throw new Error(`Invalid severity level "${level}". Must be one of: ${validLevels.join(', ')}`);
    }

    const incidents = await Incident.find({ 
      dangerLevel: level,
      status: 'open'
    }).sort({ timestamp: -1 }).lean();

    console.log(`✅ Retrieved ${incidents.length} open incident(s) at severity level "${level}"`);
    return incidents;
  } catch (error) {
    console.error('❌ Failed to retrieve incidents by severity:', error.message);
    throw error;
  }
}

module.exports = {
  Incident,
  createIncident,
  listIncidents,
  updateIncidentStatus,
  getIncident,
  getIncidentsBySeverity,
  deleteIncident,
};
