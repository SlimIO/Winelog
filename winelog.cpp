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
    std::string providerSourceName;
    std::string channel;
    std::string computer;
    std::string time;
    std::string correlationActivityID;
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

/*
 * Create a complete events logs path
 */
LPCWSTR constructEventLogPath(std::string logName) {
    char winRootPath[MAX_PATH];
    std::stringstream ss;

    GetWindowsDirectoryA(winRootPath, MAX_PATH);
    ss << winRootPath << EVENTLOG_PATH << logName << ".evtx";
    std::string logRoot = ss.str();
    std::wstring ws = s2ws(logRoot);

    return ws.c_str();
}

/**
 * @doc: https://docs.microsoft.com/en-us/windows/win32/api/winevt/ne-winevt-evt_variant_type
 * @doc: https://github.com/libyal/libevtx/blob/master/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc
 */
DWORD GetEventValues(EVT_HANDLE hEvent, LogRow *row) {
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;
    uint16_t EventID = 0;
    LPWSTR ppValues[] = {
        L"Event/System/Provider/@Name", // id: 0
        L"Event/System/Provider/@Guid", // id: 1 (opt)
        L"Event/System/Provider/@EventSourceName", // id: 2 (opt)
        L"Event/System/EventID", // id: 3
        L"Event/System/EventID/@Qualifiers", // id: 4
        L"Event/System/Version", // id: 5
        L"Event/System/Level", // id: 6
        L"Event/System/Task", // id: 7
        L"Event/System/Opcode", // id: 8
        L"Event/System/Keywords", // id: 9
        L"Event/System/TimeCreated/@SystemTime", // id: 10
        L"Event/System/EventRecordID", // id: 11
        L"Event/System/Execution/@ProcessID", // id: 12 (opt)
        L"Event/System/Execution/@ThreadID", // id: 13 (opt)
        L"Event/System/Channel", // id: 14 (opt)
        L"Event/System/Computer", //id: 15
        L"Event/System/Security/@UserID", // id: 16
        L"Event/System/Correlation/@ActivityID", // id: 17 (opt)
        L"Event/EventData/Data" // id: 18
    };
    DWORD count = sizeof(ppValues) / sizeof(LPWSTR);
    ULONGLONG ullTimeStamp = 0;
    SYSTEMTIME st;
    FILETIME ft;
    wchar_t* providerName;
    wchar_t* providerSourceName;
    wchar_t* channel;
    wchar_t* computer;
    char dateBuffer[256];

    // Identify the components of the event that you want to render. In this case,
    // render the system section of the event.
    hContext = EvtCreateRenderContext(count, (LPCWSTR*)ppValues, EvtRenderContextValues);
    if (NULL == hContext) {
        // wprintf(L"EvtCreateRenderContext failed with %lu\n", status = GetLastError());
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
                // wprintf(L"malloc failed\n");
                status = ERROR_OUTOFMEMORY;
                goto cleanup;
            }
        }

        if (ERROR_SUCCESS != (status = GetLastError())) {
            // wprintf(L"EvtRender failed with %d\n", GetLastError());
            goto cleanup;
        }
    }

    providerName = (wchar_t*) (EvtVarTypeNull == pRenderedValues[0].Type) ? L"" : pRenderedValues[0].StringVal;
    providerSourceName = (wchar_t*) (EvtVarTypeNull == pRenderedValues[2].Type) ? L"" : pRenderedValues[2].StringVal;
    row->providerName = std::string(_bstr_t(providerName));
    row->providerSourceName = std::string(_bstr_t(providerSourceName));

    EventID = pRenderedValues[3].UInt16Val;
    if (pRenderedValues[4].Type != EvtVarTypeNull) {
        EventID = MAKELONG(pRenderedValues[3].UInt16Val, pRenderedValues[4].UInt16Val);
    }
    row->eventID = EventID;

    // Handle GUID fields
    if (pRenderedValues[1].GuidVal != NULL) {
        row->providerGUID = guidToString(*(pRenderedValues[1].GuidVal));
    }
    if (pRenderedValues[17].GuidVal != NULL) {
        row->correlationActivityID = guidToString(*(pRenderedValues[17].GuidVal));
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

    // if (pRenderedValues[18].Type == EvtVarTypeString) {
    //     std::cout << "event data type: " << pRenderedValues[18].Type << " ( " << EvtVarTypeNull << " ) " << std::endl;
    //     LPWSTR* valArr = pRenderedValues[18].StringArr;
    //     while (*valArr) {
    //         wchar_t* wcharValue = (wchar_t*) valArr;
    //         // std::string valueStr = std::string(_bstr_t(wcharValue));

    //         std::wcout << "value : " << wcharValue << "\n";
    //         *valArr++;
    //     }
    // }

    cleanup:
    if (hContext) {
        EvtClose(hContext);
    }
    if (pRenderedValues) {
        free(pRenderedValues);
    }

    return status;
}

/**
 * Read event log - Asynchronous Worker
 *
 * @doc: https://docs.microsoft.com/en-us/windows/desktop/eventlog/querying-for-event-source-messages
 * @doc: https://docs.microsoft.com/en-us/windows/desktop/wes/rendering-events
 */
class LogReaderWorker : public Napi::AsyncProgressWorker<LogRow> {
    public:
        LogReaderWorker(Napi::Function& callback, LPCWSTR completeEventLogPath, const wchar_t* query, bool reverse)
        : AsyncProgressWorker(callback), completeEventLogPath(completeEventLogPath), query(query), reverse(reverse) {}
        ~LogReaderWorker() {}

    void CloseWorker() {
        closed = 1;
    }

    private:
        int closed = 0;
        bool reverse;
        LPCWSTR completeEventLogPath;
        const wchar_t* query;
        EVT_HANDLE hResults = NULL;

    void Execute(const ExecutionProgress& progress) {
        DWORD status = ERROR_SUCCESS;
        EVT_HANDLE hEvents[ARRAY_SIZE];
        DWORD dwReturned = 0;
        EVT_QUERY_FLAGS direction = reverse ? EvtQueryReverseDirection : EvtQueryForwardDirection;

        hResults = EvtQuery(NULL, completeEventLogPath, L"*", EvtQueryFilePath | direction);
        if (NULL == hResults) {
            status = GetLastError();
            if (ERROR_EVT_CHANNEL_NOT_FOUND == status) {
                SetError("ERROR_EVT_CHANNEL_NOT_FOUND - Channel not found");
            }
            else if (ERROR_EVT_INVALID_QUERY == status) {
                SetError("ERROR_EVT_INVALID_QUERY - Invalid query");
            }
            else {
                SetError("EvtQuery failed - Insufficient right");
            }

            goto cleanup;
        }

        while (true) {
            if (closed == 1) {
                break;
            }
            if (!EvtNext(hResults, ARRAY_SIZE, hEvents, INFINITE, 0, &dwReturned)) {
                // if (ERROR_NO_MORE_ITEMS != (status = GetLastError())) {
                //     wprintf(L"EvtNext failed with %lu\n", status);
                // }
                goto cleanup;
            }

            for (DWORD i = 0; i < dwReturned; i++) {
                LogRow row;
                status = GetEventValues(hEvents[i], &row);
                if (ERROR_SUCCESS != status) {
                    goto cleanup;
                }

                progress.Send(&row, 1);
                EvtClose(hEvents[i]);
                hEvents[i] = NULL;
                break;
            }
        }

        cleanup:
        for (DWORD i = 0; i < dwReturned; i++) {
            if (hEvents[i] != NULL) {
                EvtClose(hEvents[i]);
            }
        }
        if (hResults) {
            EvtClose(hResults);
        }
    }

    void OnError(const Napi::Error& e) {
        DWORD errorCode = GetLastError();
        std::stringstream error;
        error << e.what();
        if (errorCode != 0) {
            error << " - code (" << errorCode << ") - " << getLastErrorMessage();
        }

        Callback().Call({
            Napi::String::New(Env(), error.str()), Env().Null()
        });
    }

    void OnOK() {
        Napi::HandleScope scope(Env());

        Callback().Call({
            Env().Null(), Env().Null()
        });
    }

    void OnProgress(const LogRow *row, size_t /* count */) {
        Napi::HandleScope scope(Env());
        Napi::Object jsRow = Napi::Object::New(Env());

        jsRow.Set("eventId", row->eventID);
        jsRow.Set("providerName", row->providerName);
        if (row->providerGUID.empty() == false) {
            jsRow.Set("providerGUID", row->providerGUID);
        }
        if (row->providerSourceName.empty() == false) {
            jsRow.Set("providerSourceName", row->providerSourceName);
        }
        if (row->correlationActivityID.empty() == false) {
            jsRow.Set("correlationActivityGUID", row->correlationActivityID);
        }
        jsRow.Set("level", row->level);
        jsRow.Set("task", row->task);
        jsRow.Set("opcode", row->opcode);
        // TODO: use Napi::BigInt when out of experimental
        jsRow.Set("keywords", row->keywords);
        jsRow.Set("eventRecordId", row->eventRecordID);
        jsRow.Set("processId", row->processID == 0 ? Env().Null() : Napi::Number::New(Env(), row->processID));
        jsRow.Set("threadId", row->threadID == 0 ? Env().Null() : Napi::Number::New(Env(), row->threadID));
        if (row->channel.empty() == false) {
            jsRow.Set("channel", row->channel);
        }
        jsRow.Set("computer", row->computer);
        jsRow.Set("timeCreated", row->time);

        Callback().Call({
            Env().Null(),
            jsRow
        });
    }
};

/**
 * Function that will be returned to the JavaScript layer. This method is capable to close the worker!
 */
Napi::Value FreeCallback(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    LogReaderWorker* wk = (LogReaderWorker*) info.Data();
    wk->CloseWorker();

    return env.Undefined();
}

/*
 * Read a given event log (Binding interface).
 */
Napi::Value readEventLog(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    LPCWSTR completeEventLogPath;
    std::string logName;
    std::string query;
    std::wstring query_w;
    Napi::Function callback;
    bool reverse = true;

    if (info.Length() < 4) {
        Napi::Error::New(env, "Wrong number of argument provided!").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (!info[0].IsString()) {
        Napi::Error::New(env, "argument logName should be typeof string!").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (!info[1].IsString()) {
        Napi::Error::New(env, "argument query should be typeof string!").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (!info[2].IsBoolean()) {
        Napi::Error::New(env, "argument reverse should be typeof boolean!").ThrowAsJavaScriptException();
        return env.Null();
    }
    if (!info[3].IsFunction()) {
        Napi::Error::New(env, "argument callback should be typeof function!").ThrowAsJavaScriptException();
        return env.Null();
    }

    logName = info[0].As<Napi::String>().Utf8Value();
    query = info[1].As<Napi::String>().Utf8Value();
    reverse = info[2].As<Napi::Boolean>().ToBoolean();
    callback = info[3].As<Napi::Function>();

    query_w = s2ws(query.c_str());

    completeEventLogPath = constructEventLogPath(logName);
    const wchar_t* localQuery = query_w.c_str();
    LogReaderWorker *wk = new LogReaderWorker(callback, completeEventLogPath, localQuery, reverse);
    wk->Queue();
    Napi::Function free = Napi::Function::New(env, FreeCallback, "free", wk);

    return free;
}

Napi::Object Init(Napi::Env env,Napi:: Object exports) {
    exports.Set("readEventLog", Napi::Function::New(env, readEventLog));

    return exports;
}

NODE_API_MODULE(winelog, Init)
