#include <windows.h>
#include <string>
#include <iostream>
#include <stdio.h>
#include <strsafe.h>
#include "napi.h"

#define MAX_TIMESTAMP_LEN 23 + 1 // mm/dd/yyyy hh:mm:ss.mmm
#define MAX_RECORD_BUFFER_SIZE  0x10000 // 64K

using namespace std;
using namespace Napi;

// Events types name
const LPCSTR pEventTypeNames[] = {
    "Error",
    "Warning",
    "Informational",
    "Audit Success",
    "Audit Failure"
};

// Get an index value to the pEventTypeNames array based on 
// the event type value.
DWORD getEventTypeName(DWORD EventType) {
    DWORD index = 0;

    switch (EventType) {
        case EVENTLOG_ERROR_TYPE:
            index = 0;
            break;
        case EVENTLOG_WARNING_TYPE:
            index = 1;
            break;
        case EVENTLOG_INFORMATION_TYPE:
            index = 2;
            break;
        case EVENTLOG_AUDIT_SUCCESS:
            index = 3;
            break;
        case EVENTLOG_AUDIT_FAILURE:
            index = 4;
            break;
    }

    return index;
}

/*
 * Binding for retrieving drive performance
 * 
 * @doc: https://docs.microsoft.com/en-us/windows/desktop/eventlog/querying-for-event-source-messages
 */
Value readEventLog(const CallbackInfo& info) {
    HANDLE hEventLog = NULL;
    HANDLE hResources = NULL;
    DWORD status = ERROR_SUCCESS;
    DWORD dwBytesToRead = 0;
    DWORD dwBytesRead = 0;
    DWORD dwMinimumBytesToRead = 0;
    PBYTE pBuffer = NULL;
    PBYTE pTemp = NULL;
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
    string logName = info[0].As<String>().Utf8Value();
    LPCSTR providerName = logName.c_str();
    LPCSTR resourceDDL = "";
    Array ret = Array::New(env);

    // Open provided Event Log
    hEventLog = OpenEventLogA(NULL, providerName);
    if (NULL == hEventLog) {
        printf("OpenEventLog failed with (%d).\n", GetLastError());
        return env.Null();
    }

    // LoadLibrary
    // hResources = LoadLibraryExA(resourceDDL, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
    // if (NULL == hResources) {
    //     wprintf(L"LoadLibrary failed with %lu.\n", GetLastError());
    //     goto cleanup;
    // }

    // Allocate an initial block of memory used to read event records. The number 
    // of records read into the buffer will vary depending on the size of each event.
    // The size of each event will vary based on the size of the user-defined
    // data included with each event, the number and length of insertion 
    // strings, and other data appended to the end of the event record.
    unsigned int i = 0;
    dwBytesToRead = MAX_RECORD_BUFFER_SIZE;
    pBuffer = (PBYTE) malloc(dwBytesToRead);
    if (NULL == pBuffer) {
        wprintf(L"Failed to allocate the initial memory for the record buffer.\n");
        goto cleanup;
    }

    // Read blocks of records until you reach the end of the log or an 
    // error occurs. The records are read from newest to oldest. If the buffer
    // is not big enough to hold a complete event record, reallocate the buffer.
    while (ERROR_SUCCESS == status) {
        bool state = ReadEventLog(
            hEventLog, EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ, 0, pBuffer, dwBytesToRead, &dwBytesRead, &dwMinimumBytesToRead
        );
        if (!state) {
            status = GetLastError();
            if (ERROR_INSUFFICIENT_BUFFER == status) {
                status = ERROR_SUCCESS;

                pTemp = (PBYTE) realloc(pBuffer, dwMinimumBytesToRead);
                if (NULL == pTemp) {
                    wprintf(L"Failed to reallocate the memory for the record buffer (%d bytes).\n", dwMinimumBytesToRead);
                    goto cleanup;
                }

                pBuffer = pTemp;
                dwBytesToRead = dwMinimumBytesToRead;
            }
            else if (ERROR_HANDLE_EOF != status) {
                wprintf(L"ReadEventLog failed with %lu.\n", status);
                goto cleanup;
            }
        }
        else {
            PBYTE pEndOfRecords = pBuffer + dwBytesRead;
            PBYTE pRecord = pBuffer;
            while (pRecord < pEndOfRecords) {
                PEVENTLOGRECORD record = (PEVENTLOGRECORD) pRecord;
                DWORD eventType = getEventTypeName(record->EventType);
                Object recordJS = Object::New(env);
                ret[i] = recordJS;
                recordJS.Set("eventId", record->EventID);
                recordJS.Set("recordNumber", record->RecordNumber);
                recordJS.Set("timeGenerated", record->TimeGenerated);
                recordJS.Set("timeWritten", record->TimeWritten);
                recordJS.Set("eventType", pEventTypeNames[eventType]);
                i++;

                pRecord += (record)->Length;
            }
        }
    }

    // GOTO cleanup
    cleanup:
        if (hEventLog) CloseEventLog(hEventLog);
        if (pBuffer) free(pBuffer);
    
    return ret;
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
