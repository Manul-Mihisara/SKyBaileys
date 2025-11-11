//=======================================================//

console.log();
console.log("## Baileys Mod by Skyzopedia");
console.log("• https://t.me/Xskycode");
console.log("• https://whatsapp.com/channel/0029Vb6gF6kGU3BM8hcDW322");
console.log();

import makeWASocket from "./Socket/index.js";
//=======================================================//
export * from "./Defaults/index.js";
export * from "./WABinary/index.js";
export * from "../WAProto/index.js";
export * from "./WAUSync/index.js";
export * from "./Store/index.js";
export * from "./Utils/index.js";
export * from "./Types/index.js";
export * from "./WAM/index.js";
//=======================================================//
export { makeWASocket };
export default makeWASocket;
//=======================================================//