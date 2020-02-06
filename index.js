"use strict";

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
        winelog.readEventLog("Security", (row) => ee.emit("row", row));
    });

    for await (const row of on(ee, "row")) {
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
}
main().catch(console.error);

// console.time("System");
// const sysLogs = winelog.readEventLog("System");
// console.timeEnd("System");
// console.log(sysLogs.length);
