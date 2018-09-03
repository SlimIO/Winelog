/** @type {Winelog} */
const winelog = require("./build/Release/winelog.node");

console.time("readEventLog");
const appLogs = winelog.readEventLog("Application");
console.timeEnd("readEventLog");
for (const log of appLogs) {
    console.log(log);
    console.log(new Date(log.timeGenerated * 1000));
    break;
}

const securityLogs = winelog.readEventLog("Security");
console.log(securityLogs);
