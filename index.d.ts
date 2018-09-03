declare namespace Winelog {

    export enum LogType {
        Application = 0,
        System = 1,
        Security = 2,
        DirectoryService = 3,
        DNSServer = 4,
        FileReplicationService = 5
    }

    export interface EventLog {
        eventId: number;
        recordNumber: number;
        eventName: string;
        timeGenerated: number;
        timeWritten: number;
    }

    export function readEventLog(logName: Winelog.LogType): EventLog[];

}

export as namespace Winelog;
export = Winelog;
