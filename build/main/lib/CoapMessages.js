"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
class CoapMessages {
}
exports.default = CoapMessages;
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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ29hcE1lc3NhZ2VzLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9Db2FwTWVzc2FnZXMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7QUFBQSxNQUFxQixZQUFZOztBQUFqQywrQkFnRUM7QUEvRGUscUJBQVEsR0FBRyxDQUN2QixLQUF3QyxFQUN4QyxJQUFhLEVBQ0wsRUFBRTtJQUNWLE1BQU0sUUFBUSxHQUFHLElBQUksSUFBSSxPQUFPLEtBQUssQ0FBQztJQUV0QyxJQUFJLEtBQUssS0FBSyxJQUFJLEVBQUU7UUFDbEIsT0FBTyxNQUFNLENBQUMsS0FBSyxDQUFDLENBQUMsQ0FBQyxDQUFDO0tBQ3hCO0lBRUQsUUFBUSxRQUFRLEVBQUU7UUFDaEIsS0FBSyxPQUFPLENBQUMsQ0FBQztZQUNaLE1BQU0sTUFBTSxHQUFHLE1BQU0sQ0FBQyxXQUFXLENBQUMsQ0FBQyxDQUFDLENBQUM7WUFDckMsTUFBTSxDQUFDLFVBQVUsQ0FBQyxLQUFlLEVBQUUsQ0FBQyxDQUFDLENBQUM7WUFDdEMsT0FBTyxNQUFNLENBQUM7U0FDZjtRQUNELEtBQUssUUFBUSxDQUFDLENBQUM7WUFDYixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ3JDLE1BQU0sQ0FBQyxhQUFhLENBQUMsS0FBZSxFQUFFLENBQUMsQ0FBQyxDQUFDO1lBQ3pDLE9BQU8sTUFBTSxDQUFDO1NBQ2Y7UUFDRCxLQUFLLFFBQVEsQ0FBQztRQUNkLEtBQUssS0FBSyxDQUFDLENBQUM7WUFDVixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ3JDLE1BQU0sQ0FBQyxhQUFhLENBQUMsS0FBZSxFQUFFLENBQUMsQ0FBQyxDQUFDO1lBQ3pDLE9BQU8sTUFBTSxDQUFDO1NBQ2Y7UUFFRCxLQUFLLEtBQUssQ0FBQztRQUNYLEtBQUssT0FBTyxDQUFDLENBQUM7WUFDWixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ3JDLE1BQU0sQ0FBQyxZQUFZLENBQUMsS0FBZSxFQUFFLENBQUMsQ0FBQyxDQUFDO1lBQ3hDLE9BQU8sTUFBTSxDQUFDO1NBQ2Y7UUFFRCxLQUFLLE1BQU0sQ0FBQztRQUNaLEtBQUssT0FBTyxDQUFDLENBQUM7WUFDWixNQUFNLE1BQU0sR0FBRyxNQUFNLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQyxDQUFDO1lBQ3JDLE1BQU0sQ0FBQyxVQUFVLENBQUMsS0FBZSxFQUFFLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQztZQUN6QyxPQUFPLE1BQU0sQ0FBQztTQUNmO1FBRUQsS0FBSyxRQUFRLENBQUM7UUFDZCxLQUFLLFFBQVEsQ0FBQyxDQUFDO1lBQ2IsTUFBTSxNQUFNLEdBQUcsTUFBTSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQztZQUNyQyxNQUFNLENBQUMsYUFBYSxDQUFDLEtBQWUsRUFBRSxDQUFDLENBQUMsQ0FBQztZQUN6QyxPQUFPLE1BQU0sQ0FBQztTQUNmO1FBRUQsS0FBSyxRQUFRLENBQUMsQ0FBQztZQUNiLE9BQU8sTUFBTSxDQUFDLE1BQU0sQ0FBRSxLQUFpQyxDQUFDLENBQUM7U0FDMUQ7UUFFRCxLQUFLLE1BQU0sQ0FBQyxDQUFDO1lBQ1gsT0FBTyxNQUFNLENBQUMsSUFBSSxDQUFDLEtBQUssQ0FBQyxRQUFRLEVBQUUsSUFBSSxFQUFFLENBQUMsQ0FBQztTQUM1QztRQUVELEtBQUssUUFBUSxDQUFDO1FBQ2QsT0FBTyxDQUFDLENBQUM7WUFDUCxPQUFPLE1BQU0sQ0FBQyxJQUFJLENBQUMsS0FBSyxDQUFDLFFBQVEsRUFBRSxJQUFJLEVBQUUsQ0FBQyxDQUFDO1NBQzVDO0tBQ0Y7QUFDSCxDQUFDLENBQUMifQ==