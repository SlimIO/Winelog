"use strict";

// Require Node.js Dependencies
const { EventEmitter, on } = require("events");

/** @type {Winelog} */
const winelog = require("node-gyp-build")(__dirname);

// CONSTANTS
const kFiles = Object.freeze({
    Application: "Application",
    System: "System",
    Security: "Security",
    DirectoryService: "DirectoryService",
    DNSServer: "DNSServer",
    FileReplicationService: "FileReplicationService"
});

/**
 * @async
 * @generator
 * @function readEventLog
 * @param {!string} name event log name
 * @param {bool} [reverseDirection=true] switch between reverse and forward direction
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
async function* readEventLog(name, reverseDirection = true) {
    if (typeof name !== "string") {
        throw new TypeError("name must be a string");
    }

    const ee = new EventEmitter();
    const closeReadWorker = winelog.readEventLog(name, reverseDirection, (error, row) => ee.emit("row", error, row));

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

module.exports = { readEventLog, files: kFiles };
