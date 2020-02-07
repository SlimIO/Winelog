"use strict";

require("make-promises-safe");

// Require Node.js Dependencies
const { EventEmitter, on } = require("events");

/** @type {Winelog} */
const winelog = require("./build/Release/winelog.node");

// console.time("Application");
// const appLogs = winelog.readEventLog("Application");
// console.timeEnd("Application");
// for (const log of appLogs) {
//     console.log(log);
//     break;
// }

async function* readEventLog(name) {
    const ee = new EventEmitter();
    setImmediate(() => {
        // TODO: would be cool to being able to pull a close signal
        winelog.readEventLog("Security", (error, row) => ee.emit("row", error, row));
    });

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

async function main() {
    for await (const row of readEventLog("Security")) {
        console.log(row);
        break;
    }
    console.log("boo");
    await new Promise((resolve) => setTimeout(resolve, 2000));
    console.log("foo");
}
main().catch(console.error);

// console.time("System");
// const sysLogs = winelog.readEventLog("System");
// console.timeEnd("System");
// console.log(sysLogs.length);
