# Winelog
![version](https://img.shields.io/badge/dynamic/json.svg?url=https://raw.githubusercontent.com/SlimIO/Winelog/master/package.json&query=$.version&label=Version)
![N-API](https://img.shields.io/badge/N--API-v3-green.svg)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/SlimIO/Winelog/commit-activity)
[![mit](https://img.shields.io/github/license/Naereen/StrapDown.js.svg)](https://github.com/SlimIO/Winelog/blob/master/LICENSE)
![dep](https://img.shields.io/badge/Dependencies-2-yellow.svg)
![size](https://img.shields.io/github/languages/code-size/SlimIO/winelog)
![known vulnerabilities](https://img.shields.io/snyk/vulnerabilities/github/SlimIO/winelog)

Windows Events log reader - Node.JS low-level binding

## Requirements
- Node.js v12 or higher

## Getting Started

This package is available in the Node Package Repository and can be easily installed with [npm](https://docs.npmjs.com/getting-started/what-is-npm) or [yarn](https://yarnpkg.com).

```bash
$ npm i @slimio/winelog
# or
$ yarn add @slimio/winelog
```

## Usage example
```js
const { readEventLog, files } = require("@slimio/winelog");

async function main() {
    for await (const event of readEventLog(files.Security)) {
        console.log(event);
        break;
    }
}
main().catch(console.error);
```

## API

<details>
<summary>readEventLog(logName: keyof EventsLogFiles): AsyncIterableIterator< EventLog ></summary>
<br />

Return an Async iterable of EventLog.
```ts
interface EventLog {
    eventId: number;
    providerName: string;
    providerGUID: string;
    channel: string;
    computer: string;
    timeCreated: string;
    level: number;
    task: number;
    opcode: number;
    keywords: number;
    eventRecordID: number;
    processID: number;
    threadID: number;
}
```

</details>

## Contribution Guidelines
To contribute to the project, please read the [code of conduct](https://github.com/SlimIO/Governance/blob/master/COC_POLICY.md) and the guide for [N-API compilation](https://github.com/SlimIO/Governance/blob/master/docs/native_addons.md).

## Dependencies

|Name|Refactoring|Security Risk|Usage|
|---|---|---|---|
|[node-addon-api](https://github.com/nodejs/node-addon-api)|⚠️Major|Low|Node.js C++ addon api|
|[node-gyp-build](https://github.com/prebuild/node-gyp-build)|⚠️Major|Low|Node-gyp builder|

## License
MIT
