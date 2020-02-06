#include <windows.h>
#include <winevt.h>
#include <sddl.h>
#include <comdef.h>
#include <string>
#include <iostream>
#include <sstream>
#include "napi.h"

#pragma comment(lib, "wevtapi.lib")

#define EVENTLOG_PATH "\\System32\\Winevt\\Logs\\"
#define ARRAY_SIZE 10
#define TIMEOUT 1000  // 1 second; Set and use in place of INFINITE in EvtNext call

struct LogRow {
    uint16_t eventID;
    std::string providerGUID;
    std::string providerName;
    std::string channel;
    std::string computer;
    std::string time;
    uint8_t level;
    uint8_t version;
    uint8_t opcode;
    uint16_t task;
    uint32_t processID;
    uint32_t threadID;
    uint64_t keywords;
    uint64_t eventRecordID;
};

/*
 * Retrieve last message error with code of GetLastError()
 */
std::string getLastErrorMessage() {
    char err[256];
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, GetLastError(),
                  MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), err, 255, NULL);
    return std::string(err);
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

/*
 * Function to Convert GUID to std::string
 */
std::string guidToString(GUID guid) {
    char guid_cstr[39];
    snprintf(guid_cstr, sizeof(guid_cstr),
        "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
        guid.Data1, guid.Data2, guid.Data3,
        guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
        guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

    return std::string(guid_cstr);
}

DWORD GetEventValues(EVT_HANDLE hEvent, LogRow *row) {
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    LPWSTR ppValues[] = {
        L"Event/System/Provider/@Name",
        L"Event/System/Provider/@Guid",
        L"Event/System/Provider/@EventSourceName",
        L"Event/System/EventID",
        L"Event/System/EventID/@Qualifiers",
        L"Event/System/Version",
        L"Event/System/Level",
        L"Event/System/Task",
        L"Event/System/Opcode",
        L"Event/System/Keywords",
        L"Event/System/TimeCreated/@SystemTime", // 10
        L"Event/System/EventRecordID",
        L"Event/System/Execution/@ProcessID",
        L"Event/System/Execution/@ThreadID",
        L"Event/System/Channel",
        L"Event/System/Computer",
        L"Event/System/Security/@UserID"
    };
    DWORD count = sizeof(ppValues) / sizeof(LPWSTR);
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME st;
    FILETIME ft;
    wchar_t* providerName;
    wchar_t* channel;
    wchar_t* computer;
    char dateBuffer[256];

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
    if (NULL == hContext) {
        wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
        goto cleanup;
    }

    // When you render the user data or system section of the event, you must specify
    // the EvtRenderEventValues flag. The function returns an array of variant values
    // for each element in the user data or system section of the event. For user data
    // or event data, the values are returned in the same order as the elements are
    // defined in the event. For system data, the values are returned in the order defined
    // in the EVT_SYSTEM_PROPERTY_ID enumeration.
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

    providerName = (wchar_t*) (EvtVarTypeNull == pRenderedValues[0].Type) ? L"" : pRenderedValues[0].StringVal;
    row->providerName = std::string(_bstr_t(providerName));

    uint16_t EventID = 0;
    EventID = pRenderedValues[3].UInt16Val;
    if (EvtVarTypeNull != pRenderedValues[4].Type) {
        EventID = MAKELONG(pRenderedValues[3].UInt16Val, pRenderedValues[4].UInt16Val);
    }
    row->eventID = EventID;

    // Print the values from the System section of the element.
    if (NULL != pRenderedValues[1].GuidVal) {
        row->providerGUID = guidToString(*(pRenderedValues[1].GuidVal));
    }

    row->version = (EvtVarTypeNull == pRenderedValues[5].Type) ? 0 : pRenderedValues[5].ByteVal;
    row->level = (EvtVarTypeNull == pRenderedValues[6].Type) ? 0 : pRenderedValues[6].ByteVal;
    row->task = (EvtVarTypeNull == pRenderedValues[7].Type) ? 0 : pRenderedValues[7].UInt16Val;
    row->opcode = (EvtVarTypeNull == pRenderedValues[8].Type) ? 0 : pRenderedValues[8].ByteVal;
    row->keywords = pRenderedValues[9].UInt64Val;
    row->eventRecordID = pRenderedValues[11].UInt64Val;
    row->processID = (EvtVarTypeNull == pRenderedValues[12].Type) ? 0 : pRenderedValues[12].UInt32Val;
    row->threadID = (EvtVarTypeNull == pRenderedValues[13].Type) ? 0 : pRenderedValues[13].UInt32Val;

    channel = (wchar_t*) (EvtVarTypeNull == pRenderedValues[14].Type) ? L"" : pRenderedValues[14].StringVal;
    row->channel = std::string(_bstr_t(channel));
    computer = (wchar_t*) pRenderedValues[15].StringVal;
    row->computer = std::string(_bstr_t(computer));

    ullTimeStamp = pRenderedValues[10].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    FileTimeToSystemTime(&ft, &st);
    sprintf(dateBuffer, "%d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    row->time = std::string(dateBuffer);

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
DWORD GetEventLogsRow(EVT_HANDLE hResults, Napi::Env env, Napi::Function *callback) {
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
            status = GetEventValues(hEvents[i], &row);

            if (ERROR_SUCCESS == status) {
                Napi::Object jsRow = Napi::Object::New(env);

                jsRow.Set("eventId", row.eventID);
                jsRow.Set("providerName", row.providerName);
                jsRow.Set("providerGUID", row.providerGUID);
                jsRow.Set("level", row.level);
                jsRow.Set("task", row.task);
                jsRow.Set("opcode", row.opcode);
                jsRow.Set("keywords", row.keywords);
                jsRow.Set("eventRecordId", row.eventRecordID);
                jsRow.Set("processId", row.processID);
                jsRow.Set("threadId", row.threadID);
                jsRow.Set("channel", row.channel);
                jsRow.Set("computer", row.computer);
                jsRow.Set("timeCreated", row.time);

                callback->Call(env.Global(), { jsRow });
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
Napi::Value readEventLog(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hResults = NULL;
    char winRootPath[MAX_PATH];
    Napi::Array ret = Napi::Array::New(env);

    if (info.Length() < 1) {
        Napi::Error::New(env, "Wrong number of argument provided!").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (!info[0].IsString()) {
        Napi::Error::New(env, "argument logName should be typeof string!").ThrowAsJavaScriptException();
        return env.Null();
    }

    // Retrieve Windows path!
	GetWindowsDirectoryA(winRootPath, MAX_PATH);

    std::string logName = info[0].As<Napi::String>().Utf8Value();
    Napi::Function logCallback = info[1].As<Napi::Function>();
    std::stringstream ss;
    ss << winRootPath << EVENTLOG_PATH << logName << ".evtx";
    std::string logRoot = ss.str();
    std::wstring ws = s2ws(logRoot);
    LPCWSTR completeEventLogPath = ws.c_str();

    // Open Log
    hResults = EvtQuery(NULL, completeEventLogPath, L"*", EvtQueryFilePath | EvtQueryReverseDirection);
    if (NULL == hResults) {
        status = GetLastError();
        if (ERROR_EVT_CHANNEL_NOT_FOUND == status) {
            Napi::Error::New(env, "The channel was not found.").ThrowAsJavaScriptException();
        }
        else if (ERROR_EVT_INVALID_QUERY == status) {
            // You can call the EvtGetExtendedStatus function to try to get
            // additional information as to what is wrong with the query.
            Napi::Error::New(env, "The query is not valid").ThrowAsJavaScriptException();
        }
        else {
            std::stringstream error;
            error << "EvtQuery failed with code: " << status << ", message: " << getLastErrorMessage() << std::endl;
            Napi::Error::New(env, error.str()).ThrowAsJavaScriptException();
        }

        goto cleanup;
    }

    std::cout << "enter GetEventLogsRow" << "\n";
    GetEventLogsRow(hResults, env, &logCallback);
    logCallback.Call(env.Global(), { env.Null() });
    std::cout << "exit GetEventLogsRow" << "\n";

    cleanup:
    if (hResults) {
        EvtClose(hResults);
    }

    return ret;
}

Napi::Object Init(Napi::Env env,Napi:: Object exports) {
    exports.Set("readEventLog", Napi::Function::New(env, readEventLog));

    return exports;
}

NODE_API_MODULE(winelog, Init)
