#include <windows.h>
#include <winevt.h>
#include <string>
#include <iostream>
#include <sstream>
#include "napi.h"

#pragma comment(lib, "wevtapi.lib")

#define EVENTLOG_PATH "\\System32\\Winevt\\Logs\\"
#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

using namespace std;
using namespace Napi;

// Events types name
const char* pEventTypeNames[] = {
    "Error",
    "Warning",
    "Informational",
    "Audit Success",
    "Audit Failure"
};

struct LogRow {
    LPCWSTR name;
    LPCWSTR channel;
};

/*
 * Retrieve last message error with code of GetLastError()
 */
string getLastErrorMessage() {
    char err[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err, 255, NULL);
    return string(err);
}

/*
 * Convert std::string to std::wstring 
 */
std::wstring s2ws(const std::string& s) {
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0); 
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

DWORD PrintEventValues(EVT_HANDLE hEvent, LogRow *row) {
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    LPWSTR ppValues[] = {
        L"Event/System/Provider/@Name",
        L"Event/System/Channel"
    };
    DWORD count = sizeof(ppValues) / sizeof(LPWSTR);

    // Identify the components of the event that you want to render. In this case,
    // render the provider's name and channel from the system section of the event.
    // To get user data from the event, you can specify an expression such as
    // L"Event/EventData/Data[@Name=\"<data name goes here>\"]".
    hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
    if (NULL == hContext) {
        wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
        goto cleanup;
    }

    // The function returns an array of variant values for each element or attribute that
    // you want to retrieve from the event. The values are returned in the same order as 
    // you requested them.
    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
        if (ERROR_INSUFFICIENT_BUFFER == (status = GetLastError())) {
            dwBufferSize = dwBufferUsed;
            pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
            if (pRenderedValues) {
                EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount);
            }
            else {
                wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError())) {
            wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    // Print the selected values.
    row->name = pRenderedValues[0].StringVal;
    row->channel = (EvtVarTypeNull == pRenderedValues[1].Type) ? L"" : pRenderedValues[1].StringVal;

    cleanup:
    if (hContext) {
        EvtClose(hContext);
    }

    if (pRenderedValues) {
        free(pRenderedValues);
    }

    return status;
}

// Enumerate all the events in the result set. 
DWORD PrintResults(EVT_HANDLE hResults, vector<LogRow> *logs) {
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hEvents[ARRAY_SIZE];
    DWORD dwReturned = 0;

    while (true) {
        // Get a block of events from the result set.
        if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned)) {
            if (ERROR_NO_MORE_ITEMS != (status = GetLastError())) {
                wprintf(L"EvtNext failed with %lu\n", status);
            }
            goto cleanup;
        }

        // For each event, call the PrintEvent function which renders the
        // event for display. PrintEvent is shown in RenderingEvents.
        for (DWORD i = 0; i < dwReturned; i++) {
            LogRow row;
            if (ERROR_SUCCESS == (status = PrintEventValues(hEvents[i], &row))) {
                logs->push_back(row);
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
            }
            else {
                goto cleanup;
            }
        }
    }

    cleanup:
    for (DWORD i = 0; i < dwReturned; i++) {
        if (NULL != hEvents[i]) {
            EvtClose(hEvents[i]);
        }
    }

    return status;
}

/*
 * Binding for retrieving drive performance
 * 
 * @doc: https://docs.microsoft.com/en-us/windows/desktop/eventlog/querying-for-event-source-messages
 * @doc: https://docs.microsoft.com/en-us/windows/desktop/wes/rendering-events
 */
Value readEventLog(const CallbackInfo& info) {
    Env env = info.Env();
    vector<LogRow> logs;
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;

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

    // Retrieve Windows path!
    char winRootPath[MAX_PATH];
	GetWindowsDirectoryA(winRootPath, MAX_PATH);

    // Retrieve log name!
    string logName = info[0].As<String>().Utf8Value();
    stringstream ss;
    ss << winRootPath << EVENTLOG_PATH << logName << ".evtx";
    string logRoot = ss.str();
    wstring ws = s2ws(logRoot);
    LPCWSTR completeEventLogPath = ws.c_str();
    wprintf(L"path %s\n", completeEventLogPath);

    // Open Log
    hResults = EvtQuery(NULL, completeEventLogPath, L"*", EvtQueryFilePath | EvtQueryReverseDirection);
    if (NULL == hResults) {
        status = GetLastError();
        if (ERROR_EVT_CHANNEL_NOT_FOUND == status) {
            cout << "The channel was not found." << endl;
        }
        else if (ERROR_EVT_INVALID_QUERY == status) {
            // You can call the EvtGetExtendedStatus function to try to get 
            // additional information as to what is wrong with the query.
            cout << "The query is not valid." << endl;
        }
        else {
            stringstream error;
            error << "EvtQuery failed with code: " << status << ", message: " << getLastErrorMessage() << endl;
            Error::New(env, error.str()).ThrowAsJavaScriptException();
        }

        goto cleanup;
    }

    PrintResults(hResults, &logs);
    for (size_t i = 0; i < logs.size(); i++) {
        LogRow row = logs.at(i);
        wprintf(L"name: %s\n", row.name);
    }

    cleanup:
    if (hResults) {
        EvtClose(hResults);
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
