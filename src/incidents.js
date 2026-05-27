/* jslint es6:true, node:true */
'use strict';

const crypto = require('crypto');
const mongoose = require('mongoose');

// ── Mongoose Schema ────────────────────────────────────────────────────────────

const reporterMetadataSchema = new mongoose.Schema(
  {
    analyst_id: { type: String, required: true },
    client_ip:  { type: String, default: '0.0.0.0' },
  },
  { _id: false }
);

const incidentSchema = new mongoose.Schema(
  {
    incident_id: {
      type:    String,
      unique:  true,
      default: () => `INC-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
    },
    target_domain: { type: String, default: '' },
    danger_level: {
      type:    String,
      enum:    ['low', 'medium', 'high', 'critical'],
      default: 'low',
    },
    status: {
      type:    String,
      enum:    ['unresolved', 'investigating', 'resolved'],
      default: 'unresolved',
    },
    reporter_metadata: { type: reporterMetadataSchema, required: true },
  },
  {
    timestamps: true,   // adds createdAt & updatedAt automatically
    collection: 'incidents',
  }
);

// Create model only once (prevents OverwriteModelError on re-require)
const Incident = mongoose.models.Incident || mongoose.model('Incident', incidentSchema);

// ── CRUD Operations ────────────────────────────────────────────────────────────

/**
 * Creates a new phishing incident document.
 * @param {{ analystId: string, clientIp?: string, dangerLevel?: string, targetDomain?: string }} params
 * @returns {Promise<Object>} The saved incident document
 */
async function createIncident({ analystId, clientIp, dangerLevel, targetDomain } = {}) {
  const incident = new Incident({
    target_domain:     targetDomain || '',
    danger_level:      dangerLevel  || 'low',
    reporter_metadata: {
      analyst_id: analystId,
      client_ip:  clientIp || '0.0.0.0',
    },
  });

  await incident.save();
  return incident.toObject();
}

/**
 * Retrieve incidents, optionally filtered by status or danger level.
 * @param {{ status?: string, dangerLevel?: string }} filters
 * @returns {Promise<Array>}
 */
async function listIncidents(filters = {}) {
  const query = {};
  if (filters.status)      query.status       = filters.status;
  if (filters.dangerLevel) query.danger_level  = filters.dangerLevel;

  return Incident.find(query).sort({ createdAt: -1 }).lean();
}

/**
 * Updates the resolution status of an incident by its incident_id.
 * @param {string} incidentId
 * @param {string} newStatus
 * @returns {Promise<boolean>}
 */
async function updateIncidentStatus(incidentId, newStatus) {
  const validStatuses = ['unresolved', 'investigating', 'resolved'];
  if (!validStatuses.includes(newStatus)) {
    throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
  }

  const result = await Incident.updateOne(
    { incident_id: incidentId },
    { $set: { status: newStatus } }
  );

  if (result.matchedCount === 0) {
    throw new Error(`Incident ${incidentId} not found.`);
  }
  return true;
}

module.exports = {
  Incident,
  createIncident,
  listIncidents,
  updateIncidentStatus,
};
