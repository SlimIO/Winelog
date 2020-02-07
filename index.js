"use strict";

require("make-promises-safe");

// Require Node.js Dependencies
const { EventEmitter, on } = require("events");

/** @type {Winelog} */
const winelog = require("./build/Release/winelog.node");

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
 *
 * @throws {TypeError}
 */
async function* readEventLog(name) {
    if (typeof name !== "string") {
        throw new TypeError("name must be a string");
    }

    const ee = new EventEmitter();
    let closeReadWorker;
    setImmediate(() => {
        closeReadWorker = winelog.readEventLog(name, (error, row) => ee.emit("row", error, row));
    });

    try {
        for await (const [error, row] of on(ee, "row")) {
            if (error !== null) {
                throw error;
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
