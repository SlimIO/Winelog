/** @type {Winelog} */
const winelog = require("./build/Release/winelog.node");

// console.time("Application");
// const appLogs = winelog.readEventLog("Application");
// console.timeEnd("Application");
// for (const log of appLogs) {
//     console.log(log);
//     break;
// }

// console.time("Security");
// const securityLogs = winelog.readEventLog("Security");
// console.timeEnd("Security");
// for (const log of securityLogs) {
//     console.log(log);
//     break;
// }

console.time("System");
const sysLogs = winelog.readEventLog("System");
console.timeEnd("System");
for (const log of sysLogs) {
    console.log(log);
    break;
}
