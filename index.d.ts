declare namespace Winelog {
    export type EventsLogFiles = "Application" | "System" | "Security" | "Setup";

    export interface EventLog {
        eventId: number;
        providerName: string;
        providerSourceName?: string;
        providerGUID?: string;
        correlationActivityGUID?: string;
        channel?: string;
        computer: string;
        timeCreated: string;
        level: number;
        task: number;
        opcode: number;
        keywords: number;
        eventRecordID: number;
        processID: number | null;
        threadID: number | null;
    }

    interface ReadOptions {
        reverseDirection?: boolean;
        xPathQuery?: string;
    }

    export function readEventLog(logName: EventsLogFiles, options?: ReadOptions): AsyncIterableIterator<EventLog>;
    export const files: {
        [key: EventsLogFiles]: string;
    };
}

export as namespace Winelog;
export = Winelog;
