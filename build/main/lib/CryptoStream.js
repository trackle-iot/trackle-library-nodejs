"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const stream_1 = require("stream");
class CryptoStream extends stream_1.Transform {
    constructor(options) {
        super();
        // @ts-ignore
        // tslint:disable-next-line: variable-name
        this._transform = (chunk, 
        // @ts-ignore
        encoding, callback) => {
            if (!chunk.length) {
                throw new Error("CryptoStream transform error: Chunk didn't have any length");
            }
            try {
                const cipherParams = ['aes-128-cbc', this.key, this.iv];
                const cipher = this.streamType === 'encrypt'
                    ? crypto_1.default.createCipheriv(cipherParams[0].toString(), cipherParams[1], cipherParams[2])
                    : crypto_1.default.createDecipheriv(cipherParams[0].toString(), cipherParams[1], cipherParams[2]);
                const output = Buffer.concat([cipher.update(chunk), cipher.final()]);
                const ivContainer = this.streamType === 'encrypt' ? output : chunk;
                this.iv = Buffer.alloc(16);
                ivContainer.copy(this.iv, 0, 0, 16);
                this.push(output);
            }
            catch (error) {
                throw new Error(`CryptoStream transform error: ${error}`);
            }
            callback();
        };
        this.key = options.key;
        this.iv = options.iv;
        this.streamType = options.streamType;
    }
}
exports.default = CryptoStream;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvU3RyZWFtLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9DcnlwdG9TdHJlYW0udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSxvREFBNEI7QUFDNUIsbUNBQW1DO0FBVW5DLE1BQU0sWUFBYSxTQUFRLGtCQUFTO0lBS2xDLFlBQVksT0FBNkI7UUFDdkMsS0FBSyxFQUFFLENBQUM7UUFPVixhQUFhO1FBQ2IsMENBQTBDO1FBQ25DLGVBQVUsR0FBRyxDQUNsQixLQUFhO1FBQ2IsYUFBYTtRQUNiLFFBQWdCLEVBQ2hCLFFBQW1CLEVBQ25CLEVBQUU7WUFDRixJQUFJLENBQUMsS0FBSyxDQUFDLE1BQU0sRUFBRTtnQkFDakIsTUFBTSxJQUFJLEtBQUssQ0FDYiw0REFBNEQsQ0FDN0QsQ0FBQzthQUNIO1lBRUQsSUFBSTtnQkFDRixNQUFNLFlBQVksR0FBRyxDQUFDLGFBQWEsRUFBRSxJQUFJLENBQUMsR0FBRyxFQUFFLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztnQkFDeEQsTUFBTSxNQUFNLEdBQ1YsSUFBSSxDQUFDLFVBQVUsS0FBSyxTQUFTO29CQUMzQixDQUFDLENBQUMsZ0JBQU0sQ0FBQyxjQUFjLENBQ25CLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLEVBQUUsRUFDMUIsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUNmLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FDaEI7b0JBQ0gsQ0FBQyxDQUFDLGdCQUFNLENBQUMsZ0JBQWdCLENBQ3JCLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLEVBQUUsRUFDMUIsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUNmLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FDaEIsQ0FBQztnQkFFUixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsTUFBTSxDQUFDLENBQUMsTUFBTSxDQUFDLE1BQU0sQ0FBQyxLQUFLLENBQUMsRUFBRSxNQUFNLENBQUMsS0FBSyxFQUFFLENBQUMsQ0FBQyxDQUFDO2dCQUVyRSxNQUFNLFdBQVcsR0FBRyxJQUFJLENBQUMsVUFBVSxLQUFLLFNBQVMsQ0FBQyxDQUFDLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQyxLQUFLLENBQUM7Z0JBQ25FLElBQUksQ0FBQyxFQUFFLEdBQUcsTUFBTSxDQUFDLEtBQUssQ0FBQyxFQUFFLENBQUMsQ0FBQztnQkFDM0IsV0FBVyxDQUFDLElBQUksQ0FBQyxJQUFJLENBQUMsRUFBRSxFQUFFLENBQUMsRUFBRSxDQUFDLEVBQUUsRUFBRSxDQUFDLENBQUM7Z0JBRXBDLElBQUksQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDLENBQUM7YUFDbkI7WUFBQyxPQUFPLEtBQUssRUFBRTtnQkFDZCxNQUFNLElBQUksS0FBSyxDQUFDLGlDQUFpQyxLQUFLLEVBQUUsQ0FBQyxDQUFDO2FBQzNEO1lBQ0QsUUFBUSxFQUFFLENBQUM7UUFDYixDQUFDLENBQUM7UUE3Q0EsSUFBSSxDQUFDLEdBQUcsR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDO1FBQ3ZCLElBQUksQ0FBQyxFQUFFLEdBQUcsT0FBTyxDQUFDLEVBQUUsQ0FBQztRQUNyQixJQUFJLENBQUMsVUFBVSxHQUFHLE9BQU8sQ0FBQyxVQUFVLENBQUM7SUFDdkMsQ0FBQztDQTJDRjtBQUVELGtCQUFlLFlBQVksQ0FBQyJ9