import { Transform } from 'stream';

const MSG_LENGTH_BYTES = 2;
const messageLengthBytes = (message: Buffer | string): Buffer => {
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

interface IChunkingStreamOptions {
  outgoing?: boolean;
}

class ChunkingStream extends Transform {
  public expectedLength: number;
  public incomingBuffer: Buffer = null;
  public incomingIndex: number = -1;
  public outgoing: boolean;

  constructor(options: IChunkingStreamOptions) {
    super();

    this.outgoing = !!options.outgoing;
  }

  public process = (chunk: Buffer, callback: () => any) => {
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
      } else {
        process.nextTick((): void => this.process(remainder, callback));
      }
    } else {
      process.nextTick(callback);
    }
  };

  // @ts-ignore
  // tslint:disable-next-line: variable-name
  public _transform = (
    chunk: Buffer | string,
    // @ts-ignore
    encoding: string,
    callback: () => any
  ) => {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);

    if (this.outgoing) {
      // we should be passed whole messages here.
      // write our length first, then message, then bail.
      const lengthChunk = messageLengthBytes(chunk);
      this.push(Buffer.concat(lengthChunk ? [lengthChunk, buffer] : [buffer]));
      process.nextTick(callback);
    } else {
      // Collect chunks until we hit an expected size, and then trigger a
      // readable
      try {
        process.nextTick((): void => this.process(buffer, callback));
      } catch (error) {
        throw new Error(`ChunkingStream error!: ${error}`);
      }
    }
  };
}

export default ChunkingStream;
