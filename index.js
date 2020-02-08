"use strict";

// Require Node.js Dependencies
const { EventEmitter, on } = require("events");

/** @type {Winelog} */
const winelog = require("node-gyp-build")(__dirname);

// CONSTANTS
const kFiles = Object.freeze({
    Application: "Application",
    Setup: "Setup",
    System: "System",
    Security: "Security",
    DirectoryService: "DirectoryService",
    DNSServer: "DNSServer",
    FileReplicationService: "FileReplicationService",
    DFSReplication: "DFS Replication",
    HardwareEvents: "HardwareEvents",
    InternetExplorer: "Internet Explorer",
    MediaCenter: "Media Center",
    KeyManagementService: "Key Management Service",
    ODiag: "ODiag",
    OSession: "OSession"
});

const kLevels = Object.freeze({
    SuccessAudit: 0,
    FailureAudit: 1,
    Error: 2,
    Warning: 3,
    Information: 4
});

/**
 * @async
 * @generator
 * @function readEventLog
 * @param {!string} name event log name
 * @param {object} [options]
 * @param {bool} [options.reverseDirection=true] switch between reverse and forward direction
 * @param {string} [options.xPathQuery="*"] path to query
 *
 * @throws {TypeError}
 * @throws {Error}
 *
 * @example
 * for await (const event of readEventLog("Security")) {
 *     console.log(event);
 *     break;
 * }
 */
async function* readEventLog(name, options = Object.create(null)) {
    const { reverseDirection = true, xPathQuery = "*" } = options;
    const localxPathQuery = String(xPathQuery);
    if (Number.isNaN(localxPathQuery)) {
        throw new TypeError("options.xPathQuery must be a valid string value");
    }

    const ee = new EventEmitter();
    const closeReadWorker = winelog.readEventLog(String(name), localxPathQuery, Boolean(reverseDirection),
        (error, row) => ee.emit("row", error, row));

    try {
        for await (const [error, row] of on(ee, "row")) {
            if (error !== null) {
                throw new Error(error);
            }
            if (row === null) {
                break;
            }

            yield row;
        }
    }
    finally {
        closeReadWorker && closeReadWorker();
    }
}

module.exports = { readEventLog, files: kFiles, levels: kLevels };
