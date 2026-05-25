/* jslint es6:true, node:true */
const path = require('path');
const fs = require('fs');
const { getFirebase } = require('./db');
const { defangHostname } = require('./blacklist');

const INCIDENTS_COLLECTION = 'incidents';

/**
 * Validate whether the provided danger level is supported.
 * @param {string} level
 * @returns {boolean}
 */
function validateDangerLevel(level) {
  const allowed = ['low', 'medium', 'high'];
  return allowed.includes(String(level).toLowerCase());
}

/**
 * Validate whether the provided incident status is supported.
 * @param {string} status
 * @returns {boolean}
 */
function validateStatus(status) {
  const allowed = ['open', 'investigating', 'closed'];
  return allowed.includes(String(status).toLowerCase());
}

/**
 * Normalize and defang a target domain for incident storage.
 * @param {string} domain
 * @returns {string}
 */
function normalizeTargetDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return '';
  }
  return defangHostname(domain.trim());
}

/**
 * Create a new incident document in Firestore.
 * @param {Object} data
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
async function createIncident(data = {}, options = {}) {
  const { firestore, storage } = getFirebase(options);
  const incidentId = String(data.incidentId || `inc_${Date.now()}`);
  const dangerLevel = String(data.dangerLevel || 'low').toLowerCase();
  const status = String(data.status || 'open').toLowerCase();
  const reporterEmail = String(data.reporterEmail || data.reporter_email || '').trim();
  const targetDomain = normalizeTargetDomain(data.targetDomain || data.target_domain || '');

  if (!validateDangerLevel(dangerLevel)) {
    throw new Error('Invalid dangerLevel; must be low, medium, or high');
  }
  if (!validateStatus(status)) {
    throw new Error('Invalid status; must be open, investigating, or closed');
  }
  if (!reporterEmail) {
    throw new Error('reporterEmail is required');
  }
  if (!targetDomain) {
    throw new Error('targetDomain is required');
  }

  const incident = {
    incidentId,
    targetDomain,
    dangerLevel,
    reporterEmail,
    status,
    timestamp: firestore.Timestamp ? firestore.Timestamp.now() : new Date(),
  };

  await firestore.collection(INCIDENTS_COLLECTION).doc(incidentId).set(incident, { merge: false });
  return incident;
}

/**
 * Get a single incident document by its incidentId.
 * @param {string} incidentId
 * @param {Object} [options]
 * @returns {Promise<Object|null>}
 */
async function getIncident(incidentId, options = {}) {
  const { firestore } = getFirebase(options);
  const doc = await firestore.collection(INCIDENTS_COLLECTION).doc(String(incidentId)).get();
  return doc.exists ? Object.assign({ id: doc.id }, doc.data()) : null;
}

/**
 * Update the status field for an existing incident.
 * @param {string} incidentId
 * @param {string} newStatus
 * @param {Object} [options]
 * @returns {Promise<Object|null>}
 */
async function updateIncidentStatus(incidentId, newStatus, options = {}) {
  const { firestore } = getFirebase(options);
  const status = String(newStatus || '').toLowerCase();
  if (!validateStatus(status)) {
    throw new Error('Invalid status; must be open, investigating, or closed');
  }
  await firestore.collection(INCIDENTS_COLLECTION).doc(String(incidentId)).update({ status });
  return getIncident(incidentId, options);
}

/**
 * Delete an incident document by its incidentId.
 * @param {string} incidentId
 * @param {Object} [options]
 * @returns {Promise<boolean>}
 */
async function deleteIncident(incidentId, options = {}) {
  const { firestore } = getFirebase(options);
  await firestore.collection(INCIDENTS_COLLECTION).doc(String(incidentId)).delete();
  return true;
}

/**
 * Query incidents by danger level and/or status.
 * Supports both `dangerLevel` and legacy `danger_level` parameter names.
 * @param {Object} filters
 * @param {Object} [options]
 * @returns {Promise<Array<Object>>}
 */
async function getIncidentsByFilter(filters = {}, options = {}) {
  const { firestore } = getFirebase(options);
  let query = firestore.collection(INCIDENTS_COLLECTION);
  const dangerLevel = filters.dangerLevel || filters.danger_level;
  if (dangerLevel) {
    query = query.where('dangerLevel', '==', String(dangerLevel).toLowerCase());
  }
  if (filters.status) {
    query = query.where('status', '==', String(filters.status).toLowerCase());
  }
  const snap = await query.get();
  const results = [];
  snap.forEach((doc) => results.push(Object.assign({ id: doc.id }, doc.data())));
  return results;
}

/**
 * Fetch open incidents filtered by danger level.
 * @param {string} level
 * @param {Object} [options]
 * @returns {Promise<Array<Object>>}
 */
async function getIncidentsBySeverity(level, options = {}) {
  const { firestore } = getFirebase(options);
  const dangerLevel = String(level || '').toLowerCase();
  if (!validateDangerLevel(dangerLevel)) {
    throw new Error('Invalid dangerLevel; must be low, medium, or high');
  }
  const query = firestore.collection(INCIDENTS_COLLECTION)
    .where('dangerLevel', '==', dangerLevel)
    .where('status', '==', 'open');
  const snapshot = await query.get();
  const results = [];
  snapshot.forEach((doc) => results.push(Object.assign({ id: doc.id }, doc.data())));
  return results;
}

module.exports = {
  createIncident,
  getIncident,
  updateIncidentStatus,
  deleteIncident,
  getIncidentsBySeverity,
  getIncidentsByFilter,
};
