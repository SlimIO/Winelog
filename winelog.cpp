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

// Formats the specified message. If the message uses inserts, build
// the argument list to pass to FormatMessage.
LPCSTR getMessageString(HANDLE g_hResources, DWORD MessageId, DWORD argc, LPCSTR argv) {
    LPCSTR pMessage = NULL;
    DWORD dwFormatFlags = FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER;
    DWORD_PTR* pArgs = NULL;
    LPCSTR pString = argv;

    // The insertion strings appended to the end of the event record
    // are an array of strings; however, FormatMessage requires
    // an array of addresses. Create an array of DWORD_PTRs based on
    // the count of strings. Assign the address of each string
    // to an element in the array (maintaining the same order).
    if (argc > 0) {
        pArgs = (DWORD_PTR*) malloc(sizeof(DWORD_PTR) * argc);
        if (pArgs) {
            dwFormatFlags |= FORMAT_MESSAGE_ARGUMENT_ARRAY;
            for (DWORD i = 0; i < argc; i++) {
                pArgs[i] = (DWORD_PTR)pString;
                pString += strlen(pString) + 1;
            }
        }
        else {
            dwFormatFlags |= FORMAT_MESSAGE_IGNORE_INSERTS;
            printf("Failed to allocate memory for the insert string array.\n");
        }
    }

    if (!FormatMessageA(dwFormatFlags, g_hResources, MessageId, 0, (LPSTR) &pMessage, 0, (va_list*) pArgs)) {
        printf("Format message failed with %d\n", GetLastError());
    }

    if (pArgs) {
        free(pArgs);
    }

    return pMessage;
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
    hResources = LoadLibraryExA(resourceDDL, NULL, LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE);
    if (NULL == hResources) {
        printf("LoadLibrary failed with %d.\n", GetLastError());
        goto cleanup;
    }

    // Allocate an initial block of memory used to read event records. The number 
    // of records read into the buffer will vary depending on the size of each event.
    // The size of each event will vary based on the size of the user-defined
    // data included with each event, the number and length of insertion 
    // strings, and other data appended to the end of the event record.
    unsigned int i = 0;
    dwBytesToRead = MAX_RECORD_BUFFER_SIZE;
    pBuffer = (PBYTE) malloc(dwBytesToRead);
    if (NULL == pBuffer) {
        printf("Failed to allocate the initial memory for the record buffer.\n");
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
                recordJS.Set("id", record->EventID);
                recordJS.Set("recordNumber", record->RecordNumber);
                recordJS.Set("timeGenerated", record->TimeGenerated);
                recordJS.Set("timeWritten", record->TimeWritten);
                recordJS.Set("type", pEventTypeNames[eventType]);

                LPCSTR eventCategory = getMessageString(hResources, record->EventCategory, 0, NULL);
                if (eventCategory) {
                    wprintf(L"event category: %s", eventCategory);
                    eventCategory = NULL;
                }
                
                // To write the event data, you need to know the format of the data. In
                // this example, we know that the event data is a null-terminated string.
                if (record->DataLength > 0) {
                    wprintf(L"event data: %s\n", (LPWSTR) (pRecord + record->DataOffset));
                }

                i++;
                pRecord += record->Length;
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
