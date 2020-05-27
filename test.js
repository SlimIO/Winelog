"use strict";
const { readEventLog } = require("./");

async function main() {
    let count = 0;
    for await (const event of readEventLog("Security")) {
        console.log(event);
        count++;
    }
    console.log(count);
}
main().catch(console.error);
