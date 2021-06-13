import crypto from 'crypto';
import ECKey from 'ec-key';
import NodeRSA from 'node-rsa';
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
        const ecKey = new ECKey(keyPEM, 'pem');
        CryptoManager.serverKey = ecKey;
    }
    else {
        // tslint:disable-next-line: no-object-mutation
        CryptoManager.serverKey = new NodeRSA(keyPEM, 'pkcs8-public-pem', {
            encryptionScheme: 'pkcs1',
            signingScheme: 'pkcs1'
        });
    }
};
CryptoManager.loadPrivateKey = (keyPEM, algorithm) => {
    if (algorithm && algorithm === 'ecc') {
        return new ECKey(keyPEM, 'pem');
    }
    return new NodeRSA(keyPEM, 'pkcs1-private-pem', {
        encryptionScheme: 'pkcs1',
        signingScheme: 'pkcs1'
    });
};
CryptoManager.randomBytes = (count) => crypto.randomBytes(count);
CryptoManager.createHmacDigest = (ciphertext, sessionKey) => {
    const hmac = crypto.createHmac(HASH_TYPE, sessionKey);
    hmac.update(ciphertext);
    return hmac.digest();
};
export default CryptoManager;
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvTWFuYWdlci5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uLy4uLy4uL3NyYy9saWIvQ3J5cHRvTWFuYWdlci50cyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQSxPQUFPLE1BQU0sTUFBTSxRQUFRLENBQUM7QUFDNUIsT0FBTyxLQUFLLE1BQU0sUUFBUSxDQUFDO0FBQzNCLE9BQU8sT0FBTyxNQUFNLFVBQVUsQ0FBQztBQUUvQixNQUFNLFNBQVMsR0FBRyxNQUFNLENBQUM7QUFFekIsTUFBTSxhQUFhO0lBMENqQixZQUFZLFVBQW1CO1FBSXhCLFlBQU8sR0FBRyxDQUFDLE1BQWMsRUFBVSxFQUFFLENBQzFDLElBQUksQ0FBQyxVQUFVLENBQUMsY0FBYyxDQUFDLE1BQU0sQ0FBQyxDQUFDO1FBSnZDLElBQUksQ0FBQyxVQUFVLEdBQUcsVUFBVSxDQUFDO0lBQy9CLENBQUM7O0FBM0NhLDBCQUFZLEdBQUcsR0FBb0IsRUFBRSxDQUFDLGFBQWEsQ0FBQyxTQUFTLENBQUM7QUFDOUQsMEJBQVksR0FBRyxDQUFDLE1BQWMsRUFBRSxTQUFrQixFQUFFLEVBQUU7SUFDbEUsSUFBSSxTQUFTLElBQUksU0FBUyxLQUFLLEtBQUssRUFBRTtRQUNwQyxNQUFNLEtBQUssR0FBRyxJQUFJLEtBQUssQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUM7UUFDdkMsYUFBYSxDQUFDLFNBQVMsR0FBRyxLQUFLLENBQUM7S0FDakM7U0FBTTtRQUNMLCtDQUErQztRQUMvQyxhQUFhLENBQUMsU0FBUyxHQUFHLElBQUksT0FBTyxDQUFDLE1BQU0sRUFBRSxrQkFBa0IsRUFBRTtZQUNoRSxnQkFBZ0IsRUFBRSxPQUFPO1lBQ3pCLGFBQWEsRUFBRSxPQUFPO1NBQ3ZCLENBQUMsQ0FBQztLQUNKO0FBQ0gsQ0FBQyxDQUFDO0FBQ1ksNEJBQWMsR0FBRyxDQUM3QixNQUFjLEVBQ2QsU0FBa0IsRUFDRCxFQUFFO0lBQ25CLElBQUksU0FBUyxJQUFJLFNBQVMsS0FBSyxLQUFLLEVBQUU7UUFDcEMsT0FBTyxJQUFJLEtBQUssQ0FBQyxNQUFNLEVBQUUsS0FBSyxDQUFDLENBQUM7S0FDakM7SUFDRCxPQUFPLElBQUksT0FBTyxDQUFDLE1BQU0sRUFBRSxtQkFBbUIsRUFBRTtRQUM5QyxnQkFBZ0IsRUFBRSxPQUFPO1FBQ3pCLGFBQWEsRUFBRSxPQUFPO0tBQ3ZCLENBQUMsQ0FBQztBQUNMLENBQUMsQ0FBQztBQUVZLHlCQUFXLEdBQUcsQ0FBQyxLQUFhLEVBQVUsRUFBRSxDQUNwRCxNQUFNLENBQUMsV0FBVyxDQUFDLEtBQUssQ0FBQyxDQUFDO0FBRWQsOEJBQWdCLEdBQUcsQ0FDL0IsVUFBa0IsRUFDbEIsVUFBa0IsRUFDVixFQUFFO0lBQ1YsTUFBTSxJQUFJLEdBQUcsTUFBTSxDQUFDLFVBQVUsQ0FBQyxTQUFTLEVBQUUsVUFBVSxDQUFDLENBQUM7SUFDdEQsSUFBSSxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsQ0FBQztJQUN4QixPQUFPLElBQUksQ0FBQyxNQUFNLEVBQUUsQ0FBQztBQUN2QixDQUFDLENBQUM7QUFhSixlQUFlLGFBQWEsQ0FBQyJ9