"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const stream_1 = require("stream");
const MSG_LENGTH_BYTES = 2;
const messageLengthBytes = (message) => {
    // assuming a maximum encrypted message length of 65K, lets write an
    // unsigned short int before every message, so we know how much to read out.
    if (!message) {
        return null;
    }
    const length = message.length;
    const lengthBuffer = Buffer.alloc(MSG_LENGTH_BYTES);
    lengthBuffer[0] = length >>> 8;
    lengthBuffer[1] = length & 255;
    return lengthBuffer;
};
class ChunkingStream extends stream_1.Transform {
    constructor(options) {
        super();
        this.incomingBuffer = null;
        this.incomingIndex = -1;
        this.process = (chunk, callback) => {
            if (!chunk) {
                return;
            }
            const isNewMessage = this.incomingIndex === -1;
            let startIndex = 0;
            if (isNewMessage) {
                this.expectedLength = (chunk[0] << 8) + chunk[1];
                // if we don't have a buffer, make one as big as we will need.
                this.incomingBuffer = Buffer.alloc(this.expectedLength);
                this.incomingIndex = 0;
                startIndex = 2; // skip the first two.
            }
            const bytesLeft = this.expectedLength - this.incomingIndex;
            let endIndex = startIndex + bytesLeft;
            if (endIndex > chunk.length) {
                endIndex = chunk.length;
            }
            if (startIndex < endIndex && this.incomingBuffer) {
                if (this.incomingIndex >= this.incomingBuffer.length) {
                    throw new Error("hmm, shouldn't end up here.");
                }
                chunk.copy(this.incomingBuffer, this.incomingIndex, startIndex, endIndex);
            }
            this.incomingIndex += endIndex - startIndex;
            let remainder = null;
            if (endIndex < chunk.length) {
                remainder = Buffer.alloc(chunk.length - endIndex);
                chunk.copy(remainder, 0, endIndex, chunk.length);
            }
            if (this.incomingIndex === this.expectedLength && this.incomingBuffer) {
                this.push(this.incomingBuffer);
                this.incomingBuffer = null;
                this.incomingIndex = -1;
                this.expectedLength = -1;
                if (!remainder && callback) {
                    process.nextTick(callback);
                }
                else {
                    process.nextTick(() => this.process(remainder, callback));
                }
            }
            else {
                process.nextTick(callback);
            }
        };
        // @ts-ignore
        // tslint:disable-next-line: variable-name
        this._transform = (chunk, 
        // @ts-ignore
        encoding, callback) => {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            if (this.outgoing) {
                // we should be passed whole messages here.
                // write our length first, then message, then bail.
                const lengthChunk = messageLengthBytes(chunk);
                this.push(Buffer.concat(lengthChunk ? [lengthChunk, buffer] : [buffer]));
                process.nextTick(callback);
            }
            else {
                // Collect chunks until we hit an expected size, and then trigger a
                // readable
                try {
                    process.nextTick(() => this.process(buffer, callback));
                }
                catch (error) {
                    throw new Error(`ChunkingStream error!: ${error}`);
                }
            }
        };
        this.outgoing = !!options.outgoing;
    }
}
exports.default = ChunkingStream;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ2h1bmtpbmdTdHJlYW0uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbGliL0NodW5raW5nU3RyZWFtLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7O0FBQUEsbUNBQW1DO0FBRW5DLE1BQU0sZ0JBQWdCLEdBQUcsQ0FBQyxDQUFDO0FBQzNCLE1BQU0sa0JBQWtCLEdBQUcsQ0FBQyxPQUF3QixFQUFVLEVBQUU7SUFDOUQsb0VBQW9FO0lBQ3BFLDRFQUE0RTtJQUM1RSxJQUFJLENBQUMsT0FBTyxFQUFFO1FBQ1osT0FBTyxJQUFJLENBQUM7S0FDYjtJQUVELE1BQU0sTUFBTSxHQUFHLE9BQU8sQ0FBQyxNQUFNLENBQUM7SUFDOUIsTUFBTSxZQUFZLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxnQkFBZ0IsQ0FBQyxDQUFDO0lBRXBELFlBQVksQ0FBQyxDQUFDLENBQUMsR0FBRyxNQUFNLEtBQUssQ0FBQyxDQUFDO0lBQy9CLFlBQVksQ0FBQyxDQUFDLENBQUMsR0FBRyxNQUFNLEdBQUcsR0FBRyxDQUFDO0lBRS9CLE9BQU8sWUFBWSxDQUFDO0FBQ3RCLENBQUMsQ0FBQztBQU1GLE1BQU0sY0FBZSxTQUFRLGtCQUFTO0lBTXBDLFlBQVksT0FBK0I7UUFDekMsS0FBSyxFQUFFLENBQUM7UUFMSCxtQkFBYyxHQUFXLElBQUksQ0FBQztRQUM5QixrQkFBYSxHQUFXLENBQUMsQ0FBQyxDQUFDO1FBUzNCLFlBQU8sR0FBRyxDQUFDLEtBQWEsRUFBRSxRQUFtQixFQUFFLEVBQUU7WUFDdEQsSUFBSSxDQUFDLEtBQUssRUFBRTtnQkFDVixPQUFPO2FBQ1I7WUFFRCxNQUFNLFlBQVksR0FBRyxJQUFJLENBQUMsYUFBYSxLQUFLLENBQUMsQ0FBQyxDQUFDO1lBQy9DLElBQUksVUFBVSxHQUFHLENBQUMsQ0FBQztZQUNuQixJQUFJLFlBQVksRUFBRTtnQkFDaEIsSUFBSSxDQUFDLGNBQWMsR0FBRyxDQUFDLEtBQUssQ0FBQyxDQUFDLENB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