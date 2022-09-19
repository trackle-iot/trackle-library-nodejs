export default class CoapMessages {
}
CoapMessages.getTypeIntFromName = (name) => {
    switch (name) {
        case 'bool': {
            return 1;
        }
        case 'int':
        case 'int32': {
            return 2;
        }
        case 'string': {
            return 4;
        }
        case 'null': {
            return 5;
        }
        case 'long':
        case 'int64': {
            return 6;
        }
        case 'json': {
            return 7;
        }
        case 'number':
        case 'double': {
            return 9;
        }
        default: {
            return 4; // string as fallback
        }
    }
};
CoapMessages.toBinary = (value, type) => {
    const typeName = type || typeof value;
    if (value === null) {
        return Buffer.alloc(0);
    }
    switch (typeName) {
        case 'uint8': {
            const buffer = Buffer.allocUnsafe(1);
            buffer.writeUInt8(value, 0);
            return buffer;
        }
        case 'uint16': {
            const buffer = Buffer.allocUnsafe(2);
            buffer.writeUInt16BE(value, 0);
            return buffer;
        }
        case 'uint32':
        case 'crc': {
            const buffer = Buffer.allocUnsafe(4);
            buffer.writeUInt32BE(value, 0);
            return buffer;
        }
        case 'int':
        case 'int32': {
            const buffer = Buffer.allocUnsafe(4);
            buffer.writeInt32BE(value, 0);
            return buffer;
        }
        case 'long':
        case 'int64': {
            const buffer = Buffer.allocUnsafe(6);
            buffer.writeIntBE(value, 0, 6);
            return buffer;
        }
        case 'number':
        case 'double': {
            const buffer = Buffer.allocUnsafe(8);
            buffer.writeDoubleLE(value, 0);
            return buffer;
        }
        case 'buffer': {
            return Buffer.concat(value);
        }
        case 'json': {
            return Buffer.from(value.toString() || '');
        }
        case 'string':
        default: {
            return Buffer.from(value.toString() || '');
        }
    }
};
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcE1lc3NhZ2VzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9Db2FwTWVzc2FnZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsTUFBTSxDQUFDLE9BQU8sT0FBTyxZQUFZOztBQUNqQiwrQkFBa0IsR0FBRyxDQUFDLElBQVksRUFBVSxFQUFFO0lBQzFELFFBQVEsSUFBSSxFQUFFO1FBQ1osS0FBSyxNQUFNLENBQUMsQ0FBQztZQUNYLE9BQU8sQ0FBQyxDQUFDO1NBQ1Y7UUFFRCxLQUFLLEtBQUssQ0FBQztRQUNYLEtBQUssT0FBTyxDQUFDLENBQUM7WUFDWixPQUFPLENBQUMsQ0FBQztTQUNWO1FBRUQsS0FBSyxRQUFRLENBQUMsQ0FBQztZQUNiLE9BQU8sQ0FBQyxDQUFDO1NBQ1Y7UUFFRCxLQUFLLE1BQU0sQ0FBQyxDQUFDO1lBQ1gsT0FBTyxDQUFDLENBQUM7U0FDVjtRQUVELEtBQUssTUFBTSxDQUFDO1FBQ1osS0FBSyxPQUFPLENBQUMsQ0FBQztZQUNaLE9BQU8sQ0FBQyxDQUFDO1NBQ1Y7UUFFRCxLQUFLLE1BQU0sQ0FBQyxDQUFDO1lBQ1gsT0FBTyxDQUFDLENBQUM7U0FDVjtRQUVELEtBQUssUUFBUSxDQUFDO1FBQ2QsS0FBSyxRQUFRLENBQUMsQ0FBQztZQUNiLE9BQU8sQ0FBQyxDQUFDO1NBQ1Y7UUFFRCxPQUFPLENBQUMsQ0FBQztZQUNQLE9BQU8sQ0FBQyxDQUFDLENBQUMscUJBQXFCO1NBQ2hDO0tBQ0Y7QUFDSCxDQUFDLENBQUM7QUFDWSxxQkFBUSxHQUFHLENBQ3ZCLEtBQXdDLEVBQ3hDLElBQWEsRUFDTCxFQUFFO0lBQ1YsTUFBTSxRQUFRLEdBQUcsSUFBSSxJQUFJLE9BQU8sS0FBSyxDQUFDO0lBRXRDLElBQUksS0FBSyxLQUFLLElBQUksRUFBRTtRQUNsQixPQUFPLE1BQU0sQ0FBQyxLQUFLLENBQUMsQ0FBQyxDQUFDLENBQUM7S0FDeEI7SUFFRCxRQUFRLFFBQVEsRUFBRTtRQUNoQixLQUFLLE9BQU8sQ0FBQyxDQUFDO1lBQ1osTUFBTSxNQUFNLEdBQUcsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUNyQyxNQUFNLENBQUMsVUFBVSxDQUFDLEtBQWUsRUFBRSxDQUFDLENBQUMsQ0FBQztZQUN0QyxPQUFPLE1BQU0sQ0FBQztTQUNmO1FBQ0QsS0FBSyxRQUFRLENBQUMsQ0FBQztZQUNiLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDckMsTUFBTSxDQUFDLGFBQWEsQ0FBQyxLQUFlLEVBQUUsQ0FBQyxDQUFDLENBQUM7WUFDekMsT0FBTyxNQUFNLENBQUM7U0FDZjtRQUNELEtBQUssUUFBUSxDQUFDO1FBQ2QsS0FBSyxLQUFLLENBQUMsQ0FBQztZQUNWLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDckMsTUFBTSxDQUFDLGFBQWEsQ0FBQyxLQUFlLEVBQUUsQ0FBQyxDQUFDLENBQUM7WUFDekMsT0FBTyxNQUFNLENBQUM7U0FDZjtRQUVELEtBQUssS0FBSyxDQUFDO1FBQ1gsS0FBSyxPQUFPLENBQUMsQ0FBQztZQUNaLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDckMsTUFBTSxDQUFDLFlBQVksQ0FBQyxLQUFlLEVBQUUsQ0FBQyxDQUFDLENBQUM7WUFDeEMsT0FBTyxNQUFNLENBQUM7U0FDZjtRQUVELEtBQUssTUFBTSxDQUFDO1FBQ1osS0FBSyxPQUFPLENBQUMsQ0FBQztZQUNaLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDckMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxLQUFlLEVBQUUsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDO1lBQ3pDLE9BQU8sTUFBTSxDQUFDO1NBQ2Y7UUFFRCxLQUFLLFFBQVEsQ0FBQztRQUNkLEtBQUssUUFBUSxDQUFDLENBQUM7WUFDYixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ3JDLE1BQU0sQ0FBQyxhQUFhLENBQUMsS0FBZSxFQUFFLENBQUMsQ0FBQyxDQUFDO1lBQ3pDLE9BQU8sTUFBTSxDQUFDO1NBQ2Y7UUFFRCxLQUFLLFFBQVEsQ0FBQyxDQUFDO1lBQ2IsT0FBTyxNQUFNLENBQUMsTUFBTSxDQUFFLEtBQWlDLENBQUMsQ0FBQztTQUMxRDtRQUVELEtBQUssTUFBTSxDQUFDLENBQUM7WUFDWCxPQUFPLE1BQU0sQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO1NBQzVDO1FBRUQsS0FBSyxRQUFRLENBQUM7UUFDZCxPQUFPLENBQUMsQ0FBQztZQUNQLE9BQU8sTUFBTSxDQUFDLElBQUksQ0FBQyxLQUFLLENBQUMsUUFBUSxFQUFFLElBQUksRUFBRSxDQUFDLENBQUM7U0FDNUM7S0FDRjtBQUNILENBQUMsQ0FBQyJ9