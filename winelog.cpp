#include <windows.h>
#include <string>
#include "napi.h"

using namespace std;
using namespace Napi;

/*
 * Binding for retrieving drive performance
 * 
 * @doc: https://docs.microsoft.com/en-us/windows/desktop/eventlog/querying-for-event-source-messages
 */
Value readEventLog(const CallbackInfo& info) {
    Env env = info.Env();

        // Check argument length!
    if (info.Length() < 1) {
        Error::New(env, "Wrong number of argument provided!").ThrowAsJavaScriptException();
        return env.Null();
    }

    // driveName should be typeof Napi::String
    if (!info[0].IsString()) {
        Error::New(env, "argument logName should be typeof string!").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Retrieve log name!
    const char* logName = info[0].As<String>().Utf8Value().c_str();
    const char* resourceDDL = "";

    // Open provided Event Log
    HANDLE hEventLog = OpenEventLogA(NULL, logName);
    if (NULL == hEventLog) {
        printf("OpenEventLog failed with (%d).\n", GetLastError());
        return env.Null();
    }

    HANDLE hResources = LoadLibraryExA(resourceDDL, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
    if (NULL == hResources) {
        wprintf(L"LoadLibrary failed with %lu.\n", GetLastError());
        CloseEventLog(hEventLog);
    }
    
    return env.Null();
}


// Initialize Native Addon
Object Init(Env env, Object exports) {

    // Setup methods
    // TODO: Launch with AsyncWorker to avoid event loop starvation
    exports.Set("readEventLog", Function::New(env, readEventLog));

    return exports;
}

// Export
NODE_API_MODULE(winelog, Init)
