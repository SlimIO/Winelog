#include <windows.h>
#include <winevt.h>
#include <sddl.h>
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

struct LogRow {
    uint16_t eventID;
    std::string providerGUID;
    std::string ActivityID;
    std::string RelatedActivityID;
    const wchar_t* providerName;
    LPCWSTR channel;
    const wchar_t* computer;
    LPSTR securityUserID;
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
    LPSTR pwsSid = NULL;
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME st;
    FILETIME ft;

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
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

    row->providerName = std::wstring(pRenderedValues[EvtSystemProviderName].StringVal).c_str();

    uint16_t EventID = 0;
    EventID = pRenderedValues[EvtSystemEventID].UInt16Val;
    if (EvtVarTypeNull != pRenderedValues[EvtSystemQualifiers].Type) {
        EventID = MAKELONG(pRenderedValues[EvtSystemEventID].UInt16Val, pRenderedValues[EvtSystemQualifiers].UInt16Val);
    }
    row->eventID = EventID;

    // Print the values from the System section of the element.
    if (NULL != pRenderedValues[EvtSystemProviderGuid].GuidVal) {
        row->providerGUID = guidToString(*(pRenderedValues[EvtSystemProviderGuid].GuidVal));
    }

    row->version = (EvtVarTypeNull == pRenderedValues[EvtSystemVersion].Type) ? 0 : pRenderedValues[EvtSystemVersion].ByteVal;
    row->level = (EvtVarTypeNull == pRenderedValues[EvtSystemVersion].Type) ? 0 : pRenderedValues[EvtSystemVersion].ByteVal;
    row->task = (EvtVarTypeNull == pRenderedValues[EvtSystemTask].Type) ? 0 : pRenderedValues[EvtSystemTask].UInt16Val;
    row->opcode = (EvtVarTypeNull == pRenderedValues[EvtSystemOpcode].Type) ? 0 : pRenderedValues[EvtSystemOpcode].ByteVal;
    row->keywords = pRenderedValues[EvtSystemKeywords].UInt64Val;
    row->eventRecordID = pRenderedValues[EvtSystemEventRecordId].UInt64Val;
    row->processID = pRenderedValues[EvtSystemProcessID].UInt32Val;
    row->threadID = pRenderedValues[EvtSystemThreadID].UInt32Val;
    row->channel = (EvtVarTypeNull == pRenderedValues[EvtSystemChannel].Type) ? L"" : pRenderedValues[EvtSystemChannel].StringVal;
    row->computer = std::wstring(pRenderedValues[EvtSystemComputer].StringVal).c_str();

    ullTimeStamp = pRenderedValues[EvtSystemTimeCreated].FileTimeVal;
    ft.dwHighDateTime = (DWORD)((ullTimeStamp >> 32) & 0xFFFFFFFF);
    ft.dwLowDateTime = (DWORD)(ullTimeStamp & 0xFFFFFFFF);
    FileTimeToSystemTime(&ft, &st);

    char dateBuffer[256];
    sprintf(dateBuffer,
        "%d-%02d-%02d %02d:%02d:%02d.%03d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    row->time = dateBuffer;

    if (EvtVarTypeNull != pRenderedValues[EvtSystemActivityID].Type) {
        row->ActivityID = guidToString(*(pRenderedValues[EvtSystemActivityID].GuidVal));
    }

    if (EvtVarTypeNull != pRenderedValues[EvtSystemRelatedActivityID].Type) {
        row->RelatedActivityID = guidToString(*(pRenderedValues[EvtSystemRelatedActivityID].GuidVal));
    }

    if (EvtVarTypeNull != pRenderedValues[EvtSystemUserID].Type) {
        if (ConvertSidToStringSidA(pRenderedValues[EvtSystemUserID].SidVal, &pwsSid)) {
            row->securityUserID = pwsSid;
            LocalFree(pwsSid);
        }
    }

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
DWORD GetEventLogsRow(EVT_HANDLE hResults, vector<LogRow> *logs) {
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
            if (ERROR_SUCCESS == (status = GetEventValues(hEvents[i], &row))) {
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
    Napi::Array ret = Napi::Array::New(env);

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

    GetEventLogsRow(hResults, &logs);
    for (size_t i = 0; i < logs.size(); i++) {
        Napi::Object jsRow = Napi::Object::New(env);
        ret[i] = jsRow;

        LogRow row = logs.at(i);
        jsRow.Set("eventId", row.eventID);
        jsRow.Set("providerName", (const char*) row.providerName);
        jsRow.Set("computer", (const char*) row.computer);
        jsRow.Set("timeCreated", row.time);
        if (i > 3) {
            break;
        }
    }

    cleanup:
    if (hResults) {
        EvtClose(hResults);
    }

    return ret;
}

// Initialize Native Addon
Object Init(Env env, Object exports) {
    exports.Set("readEventLog", Function::New(env, readEventLog));

    return exports;
}

// Export
NODE_API_MODULE(winelog, Init)
