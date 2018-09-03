#include <windows.h>
#include "napi.h"
using namespace Napi;


// Initialize Native Addon
Object Init(Env env, Object exports) {

    // Setup methods
    // TODO: Launch with AsyncWorker to avoid event loop starvation
    // exports.Set("getLogicalDrives", Function::New(env, getLogicalDrives));

    return exports;
}

// Export
NODE_API_MODULE(winelog, Init)
