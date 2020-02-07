declare namespace Winelog {
    export interface EventsLogFiles {
        Application: string;
        System: string;
        Security: string;
        DirectoryService: string;
        DNSServer: string;
        FileReplicationService: string;
    }

    export interface EventLog {
        eventId: number;
        providerName: string;
        providerGUID: string;
        channel: string;
        computer: string;
        timeCreated: string;
        level: number;
        task: number;
        opcode: number;
        keywords: number;
        eventRecordID: number;
        processID: number;
        threadID: number;
    }

    export function readEventLog(logName: keyof EventsLogFiles, reverseDirection?: boolean): AsyncIterableIterator<EventLog>;
    export const files: EventsLogFiles;
}

export as namespace Winelog;
export = Winelog;
