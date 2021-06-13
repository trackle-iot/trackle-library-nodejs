/// <reference types="node" />
import { Transform } from 'stream';
interface IChunkingStreamOptions {
    outgoing?: boolean;
}
declare class ChunkingStream extends Transform {
    expectedLength: number;
    incomingBuffer: Buffer;
    incomingIndex: number;
    outgoing: boolean;
    constructor(options: IChunkingStreamOptions);
    process: (chunk: Buffer, callback: () => any) => void;
    _transform: (chunk: Buffer | string, encoding: string, callback: () => any) => void;
}
export default ChunkingStream;
