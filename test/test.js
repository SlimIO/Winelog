"use strict";

// Require Third-party Dependencies
const avaTest = require("ava");
const is = require("@slimio/is");

// Require Internal Dependencies
const winServices = require("../");

avaTest("winServices must export a files constants", (assert) => {
    const hasFiles = Reflect.has(winServices, "files");
    assert.true(hasFiles);
    assert.true(Object.isFrozen(winServices.files));
    assert.deepEqual(Object.keys(winServices.files).sort(), [
        "Application", "Security", "System", "DirectoryService", "DNSServer", "FileReplicationService"
    ].sort());
});

avaTest("winServices.readEventLog must be an async iterable that return event log Objects", async(assert) => {
    const asyncIterator = winServices.readEventLog(winServices.files.Security);
    assert.true(is.asyncIterable(asyncIterator));

    for await (const event of asyncIterator) {
        assert.true(is.plainObject(event));
        assert.is(typeof event.eventId, "number");
        assert.is(typeof event.providerName, "string");
        assert.is(typeof event.providerGUID, "string");
        break;
    }
});
