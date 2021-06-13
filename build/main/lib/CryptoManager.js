"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const crypto_1 = __importDefault(require("crypto"));
const ec_key_1 = __importDefault(require("ec-key"));
const node_rsa_1 = __importDefault(require("node-rsa"));
const HASH_TYPE = 'sha1';
class CryptoManager {
    constructor(privateKey) {
        this.encrypt = (buffer) => this.privateKey.encryptPrivate(buffer);
        this.privateKey = privateKey;
    }
}
CryptoManager.getServerKey = () => CryptoManager.serverKey;
CryptoManager.setServerKey = (keyPEM, algorithm) => {
    if (algorithm && algorithm === 'ecc') {
        const ecKey = new ec_key_1.default(keyPEM, 'pem');
        CryptoManager.serverKey = ecKey;
    }
    else {
        // tslint:disable-next-line: no-object-mutation
        CryptoManager.serverKey = new node_rsa_1.default(keyPEM, 'pkcs8-public-pem', {
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
        });
    }
};
CryptoManager.loadPrivateKey = (keyPEM, algorithm) => {
    if (algorithm && algorithm === 'ecc') {
        return new ec_key_1.default(keyPEM, 'pem');
    }
    return new node_rsa_1.default(keyPEM, 'pkcs1-private-pem', {
        encryptionScheme: 'pkcs1',
        signingScheme: 'pkcs1'
    });
};
CryptoManager.randomBytes = (count) => crypto_1.default.randomBytes(count);
CryptoManager.createHmacDigest = (ciphertext, sessionKey) => {
    const hmac = crypto_1.default.createHmac(HASH_TYPE, sessionKey);
    hmac.update(ciphertext);
    return hmac.digest();
};
exports.default = CryptoManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvTWFuYWdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvQ3J5cHRvTWFuYWdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiOzs7OztBQUFBLG9EQUE0QjtBQUM1QixvREFBMkI7QUFDM0Isd0RBQStCO0FBRS9CLE1BQU0sU0FBUyxHQUFHLE1BQU0sQ0FBQztBQUV6QixNQUFNLGFBQWE7SUEwQ2pCLFlBQVksVUFBbUI7UUFJeEIsWUFBTyxHQUFHLENBQUMsTUFBYyxFQUFVLEVBQUUsQ0FDMUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxjQUFjLENBQUMsTUFBTSxDQUFDLENBQUM7UUFKdkMsSUFBSSxDQUFDLFVBQVUsR0FBRyxVQUFVLENBQUM7SUFDL0IsQ0FBQzs7QUEzQ2EsMEJBQVksR0FBRyxHQUFvQixFQUFFLENBQUMsYUFBYSxDQUFDLFNBQVMsQ0FBQztBQUM5RCwwQkFBWSxHQUFHLENBQUMsTUFBYyxFQUFFLFNBQWtCLEVBQUUsRUFBRTtJQUNsRSxJQUFJLFNBQVMsSUFBSSxTQUFTLEtBQUssS0FBSyxFQUFFO1FBQ3BDLE1BQU0sS0FBSyxHQUFHLElBQUksZ0JBQUssQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDdkMsYUFBYSxDQUFDLFNBQVMsR0FBRyxLQUFLLENBQUM7S0FDakM7U0FBTTtRQUNMLCtDQUErQztRQUMvQyxhQUFhLENBQUMsU0FBUyxHQUFHLElBQUksa0JBQU8sQ0FBQyxNQUFNLEVBQUUsa0JBQWtCLEVBQUU7WUFDaEUsZ0JBQWdCLEVBQUUsT0FBTztZQUN6QixhQUFhLEVBQUUsT0FBTztTQUN2QixDQUFDLENBQUM7S0FDSjtBQUNILENBQUMsQ0FBQztBQUNZLDRCQUFjLEdBQUcsQ0FDN0IsTUFBYyxFQUNkLFNBQWtCLEVBQ0QsRUFBRTtJQUNuQixJQUFJLFNBQVMsSUFBSSxTQUFTLEtBQUssS0FBSyxFQUFFO1FBQ3BDLE9BQU8sSUFBSSxnQkFBSyxDQUFDLE1BQU0sRUFBRSxLQUFLLENBQUMsQ0FBQztLQUNqQztJQUNELE9BQU8sSUFBSSxrQkFBTyxDQUFDLE1BQU0sRUFBRSxtQkFBbUIsRUFBRTtRQUM5QyxnQkFBZ0IsRUFBRSxPQUFPO1FBQ3pCLGFBQWEsRUFBRSxPQUFPO0tBQ3ZCLENBQUMsQ0FBQztBQUNMLENBQUMsQ0FBQztBQUVZLHlCQUFXLEdBQUcsQ0FBQyxLQUFhLEVBQVUsRUFBRSxDQUNwRCxnQkFBTSxDQUFDLFdBQVcsQ0FBQyxLQUFLLENBQUMsQ0FBQztBQUVkLDhCQUFnQixHQUFHLENBQy9CLFVBQWtCLEVBQ2xCLFVBQWtCLEVBQ1YsRUFBRTtJQUNWLE1BQU0sSUFBSSxHQUFHLGdCQUFNLENBQUMsVUFBVSxDQUFDLFNBQVMsRUFBRSxVQUFVLENBQUMsQ0FBQztJQUN0RCxJQUFJLENBQUMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxDQUFDO0lBQ3hCLE9BQU8sSUFBSSxDQUFDLE1BQU0sRUFBRSxDQUFDO0FBQ3ZCLENBQUMsQ0FBQztBQWFKLGtCQUFlLGFBQWEsQ0FBQyJ9