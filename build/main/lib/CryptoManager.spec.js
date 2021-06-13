"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const ava_1 = __importDefault(require("ava"));
const CryptoManager_1 = __importDefault(require("./CryptoManager"));
// tslint:disable: no-expression-statement
ava_1.default('randomBytes', t => {
    t.truthy(Buffer.isBuffer(CryptoManager_1.default.randomBytes(5)));
    t.is(CryptoManager_1.default.randomBytes(5).length, 5);
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiQ3J5cHRvTWFuYWdlci5zcGVjLmpzIiwic291cmNlUm9vdCI6IiIsInNvdXJjZXMiOlsiLi4vLi4vLi4vc3JjL2xpYi9DcnlwdG9NYW5hZ2VyLnNwZWMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7QUFBQSw4Q0FBdUI7QUFDdkIsb0VBQTRDO0FBRTVDLDBDQUEwQztBQUMxQyxhQUFJLENBQUMsYUFBYSxFQUFFLENBQUMsQ0FBQyxFQUFFO0lBQ3RCLENBQUMsQ0FBQyxNQUFNLENBQUMsTUFBTSxDQUFDLFFBQVEsQ0FBQyx1QkFBYSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDeEQsQ0FBQyxDQUFDLEVBQUUsQ0FBQyx1QkFBYSxDQUFDLFdBQVcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxNQUFNLEVBQUUsQ0FBQyxDQUFDLENBQUM7QUFDL0MsQ0FBQyxDQUFDLENBQUMifQ==