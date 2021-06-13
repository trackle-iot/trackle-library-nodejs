import { Transform } from 'stream';
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
class ChunkingStream extends Transform {
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
export default ChunkingStream;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ2h1bmtpbmdTdHJlYW0uanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi9zcmMvbGliL0NodW5raW5nU3RyZWFtLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE9BQU8sRUFBRSxTQUFTLEVBQUUsTUFBTSxRQUFRLENBQUM7QUFFbkMsTUFBTSxnQkFBZ0IsR0FBRyxDQUFDLENBQUM7QUFDM0IsTUFBTSxrQkFBa0IsR0FBRyxDQUFDLE9BQXdCLEVBQVUsRUFBRTtJQUM5RCxvRUFBb0U7SUFDcEUsNEVBQTRFO0lBQzVFLElBQUksQ0FBQyxPQUFPLEVBQUU7UUFDWixPQUFPLElBQUksQ0FBQztLQUNiO0lBRUQsTUFBTSxNQUFNLEdBQUcsT0FBTyxDQUFDLE1BQU0sQ0FBQztJQUM5QixNQUFNLFlBQVksR0FBRyxNQUFNLENBQUMsS0FBSyxDQUFDLGdCQUFnQixDQUFDLENBQUM7SUFFcEQsWUFBWSxDQUFDLENBQUMsQ0FBQyxHQUFHLE1BQU0sS0FBSyxDQUFDLENBQUM7SUFDL0IsWUFBWSxDQUFDLENBQUMsQ0FBQyxHQUFHLE1BQU0sR0FBRyxHQUFHLENBQUM7SUFFL0IsT0FBTyxZQUFZLENBQUM7QUFDdEIsQ0FBQyxDQUFDO0FBTUYsTUFBTSxjQUFlLFNBQVEsU0FBUztJQU1wQyxZQUFZLE9BQStCO1FBQ3pDLEtBQUssRUFBRSxDQUFDO1FBTEgsbUJBQWMsR0FBVyxJQUFJLENBQUM7UUFDOUIsa0JBQWEsR0FBVyxDQUFDLENBQUMsQ0FBQztRQVMzQixZQUFPLEdBQUcsQ0FBQyxLQUFhLEVBQUUsUUFBbUIsRUFBRSxFQUFFO1lBQ3RELElBQUksQ0FBQyxLQUFLLEVBQUU7Z0JBQ1YsT0FBTzthQUNSO1lBRUQsTUFBTSxZQUFZLEdBQUcsSUFBSSxDQUFDLGFBQWEsS0FBSyxDQUFDLENBQUMsQ0FBQztZQUMvQyxJQUFJLFVBQVUsR0FBRyxDQUFDLENBQUM7WUFDbkIsSUFBSSxZQUFZLEVBQUU7Z0JBQ2hCLElBQUksQ0FBQyxjQUFjLEdB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