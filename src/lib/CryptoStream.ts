import crypto from 'crypto';
import { Transform } from 'stream';

export type CryptoStreamType = 'decrypt' | 'encrypt';

interface ICryptoStreamOptions {
  iv: Buffer;
  key: Buffer;
  streamType: CryptoStreamType;
}

class CryptoStream extends Transform {
  private key: Buffer;
  private iv: Buffer;
  private streamType: CryptoStreamType;

  constructor(options: ICryptoStreamOptions) {
    super();

    this.key = options.key;
    this.iv = options.iv;
    this.streamType = options.streamType;
  }

  // @ts-ignore
  // tslint:disable-next-line: variable-name
  public _transform = (
    chunk: Buffer,
    // @ts-ignore
    encoding: string,
    callback: () => any
  ) => {
    if (!chunk.length) {
      throw new Error(
        "CryptoStream transform error: Chunk didn't have any length"
      );
    }

    try {
      const cipherParams = ['aes-128-cbc', this.key, this.iv];
      const cipher =
        this.streamType === 'encrypt'
          ? crypto.createCipheriv(
              cipherParams[0].toString(),
              cipherParams[1],
              cipherParams[2]
            )
          : crypto.createDecipheriv(
              cipherParams[0].toString(),
              cipherParams[1],
              cipherParams[2]
            );

      const output = Buffer.concat([cipher.update(chunk), cipher.final()]);

      const ivContainer = this.streamType === 'encrypt' ? output : chunk;
      this.iv = Buffer.alloc(16);
      ivContainer.copy(this.iv, 0, 0, 16);

      this.push(output);
    } catch (error) {
      throw new Error(`CryptoStream transform error: ${error}`);
    }
    callback();
  };
}

export default CryptoStream;
