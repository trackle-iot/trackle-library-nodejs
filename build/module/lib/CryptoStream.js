import crypto from 'crypto';
import { Transform } from 'stream';
class CryptoStream extends Transform {
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
                    ? crypto.createCipheriv(cipherParams[0].toString(), cipherParams[1], cipherParams[2])
                    : crypto.createDecipheriv(cipherParams[0].toString(), cipherParams[1], cipherParams[2]);
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
export default CryptoStream;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvU3RyZWFtLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9DcnlwdG9TdHJlYW0udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxNQUFNLE1BQU0sUUFBUSxDQUFDO0FBQzVCLE9BQU8sRUFBRSxTQUFTLEVBQUUsTUFBTSxRQUFRLENBQUM7QUFVbkMsTUFBTSxZQUFhLFNBQVEsU0FBUztJQUtsQyxZQUFZLE9BQTZCO1FBQ3ZDLEtBQUssRUFBRSxDQUFDO1FBT1YsYUFBYTtRQUNiLDBDQUEwQztRQUNuQyxlQUFVLEdBQUcsQ0FDbEIsS0FBYTtRQUNiLGFBQWE7UUFDYixRQUFnQixFQUNoQixRQUFtQixFQUNuQixFQUFFO1lBQ0YsSUFBSSxDQUFDLEtBQUssQ0FBQyxNQUFNLEVBQUU7Z0JBQ2pCLE1BQU0sSUFBSSxLQUFLLENBQ2IsNERBQTRELENBQzdELENBQUM7YUFDSDtZQUVELElBQUk7Z0JBQ0YsTUFBTSxZQUFZLEdBQUcsQ0FBQyxhQUFhLEVBQUUsSUFBSSxDQUFDLEdBQUcsRUFBRSxJQUFJLENBQUMsRUFBRSxDQUFDLENBQUM7Z0JBQ3hELE1BQU0sTUFBTSxHQUNWLElBQUksQ0FBQyxVQUFVLEtBQUssU0FBUztvQkFDM0IsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxjQUFjLENBQ25CLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FBQyxRQUFRLEVBQUUsRUFDMUIsWUFBWSxDQUFDLENBQUMsQ0FBQyxFQUNmLFlBQVksQ0FBQyxDQUFDLENBQUMsQ0FDaEI7b0JBQ0gsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxnQkFBZ0IsQ0FDckIsWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBRSxFQUMxQixZQUFZLENBQUMsQ0FBQyxDQUFDLEVBQ2YsWUFBWSxDQUFDLENBQUMsQ0FBQyxDQUNoQixDQUFDO2dCQUVSLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxNQUFNLENBQUMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxFQUFFLE1BQU0sQ0FBQyxLQUFLLEVBQUUsQ0FBQyxDQUFDLENBQUM7Z0JBRXJFLE1BQU0sV0FBVyxHQUFHLElBQUksQ0FBQyxVQUFVLEtBQUssU0FBUyxDQUFDLENBQUMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEtBQUssQ0FBQztnQkFDbkUsSUFBSSxDQUFDLEVBQUUsR0FBRyxNQUFNLENBQUMsS0FBSyxDQUFDLEVBQUUsQ0FBQyxDQUFDO2dCQUMzQixXQUFXLENBQUMsSUFBSSxDQUFDLElBQUksQ0FBQyxFQUFFLEVBQUUsQ0FBQyxFQUFFLENBQUMsRUFBRSxFQUFFLENBQUMsQ0FBQztnQkFFcEMsSUFBSSxDQUFDLElBQUksQ0FBQyxNQUFNLENBQUMsQ0FBQzthQUNuQjtZQUFDLE9BQU8sS0FBSyxFQUFFO2dCQUNkLE1BQU0sSUFBSSxLQUFLLENBQUMsaUNBQWlDLEtBQUssRUFBRSxDQUFDLENBQUM7YUFDM0Q7WUFDRCxRQUFRLEVBQUUsQ0FBQztRQUNiLENBQUMsQ0FBQztRQTdDQSxJQUFJLENBQUMsR0FBRyxHQUFHLE9BQU8sQ0FBQyxHQUFHLENBQUM7UUFDdkIsSUFBSSxDQUFDLEVBQUUsR0FBRyxPQUFPLENBQUMsRUFBRSxDQUFDO1FBQ3JCLElBQUksQ0FBQyxVQUFVLEdBQUcsT0FBTyxDQUFDLFVBQVUsQ0FBQztJQUN2QyxDQUFDO0NBMkNGO0FBRUQsZUFBZSxZQUFZLENBQUMifQ==