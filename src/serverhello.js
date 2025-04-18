//@ts-self-types="../type/serverhello.d.ts"
import { Cipher, Extension, ExtensionType, KeyShareServerHello, unity, Selected_version, Uint16, Uint24, Version, KeyShareHelloRetryRequest } from "./dep.ts";
import { parseItems } from "./utils.js";

export class ServerHello extends Uint8Array {
   #legacy_version // 0x0303;    /* TLS v1.2 */
   #random
   #legacy_session_id_echo
   #cipher_suite
   #legacy_compression_method
   #extensions
   #group
   static create(...args) {
      return new ServerHello(...args)
   }
   static from = ServerHello.create
   constructor(...args) {
      sanitize(args)
      super(...args)
   }
   get version() {
      this.#legacy_version ||= Version.from(this.subarray(0, 2))
      return this.#legacy_version
   }
   get random() {
      this.#random ||= this.subarray(2, 34);
      return this.#random;
   }
   get legacy_session_id() {
      if (this.#legacy_session_id_echo) return this.#legacy_session_id_echo
      const lengthOf = this.at(34);
      if (lengthOf == 0) {
         this.#legacy_session_id_echo = this.subarray(34, 35);
         this.#legacy_session_id_echo.end = 35
      } else {
         this.#legacy_session_id_echo = this.subarray(35, 35 + lengthOf);
         this.#legacy_session_id_echo.end = 35 + lengthOf;
      }
      return this.#legacy_session_id_echo
   }
   get cipher() {
      this.#cipher_suite ||= Cipher.from(this.subarray(this.legacy_session_id.end));
      this.#cipher_suite.end = this.legacy_session_id.end + this.#cipher_suite.length;
      return this.#cipher_suite;
   }
   get legacy_compression_methods() {
      const start = this.cipher.end;
      this.#legacy_compression_method ||= this.subarray(start, start + 1);
      this.#legacy_compression_method.end = start + 1;
      return this.#legacy_compression_method
   }
   get extensions() {
      if (this.#extensions) return this.#extensions;
      const copy = this.subarray(this.legacy_compression_methods.end)
      const lengthOf = Uint16.from(copy).value;
      const output = new Map;
      for (let offset = 2; offset < lengthOf + 2;) {
         const extension = Extension.from(copy.subarray(offset)); offset += extension.length
         parseExtension(extension, this.isHRR);
         output.set(extension.type, extension)
      }
      this.#extensions ||= output;
      return this.#extensions
   }
   get handshake() {
      const handshake = unity(2, Uint24.fromValue(this.length), this)
      handshake.group = this.group;
      handshake.cipher = this.cipher;
      handshake.message = this;
      return handshake;
   }
   get record() {
      const handshake = this.handshake
      const record = unity(22, Version.legacy.byte, Uint16.fromValue(handshake.length), handshake)
      record.fragment = handshake;
      record.group = handshake.group;
      record.cipher = handshake.cipher
      return record;
   }
   get isHRR() {
      return this.random.toString() == "207,33,173,116,229,154,97,17,190,29,140,2,30,101,184,145,194,162,17,22,122,187,140,94,7,158,9,226,200,168,51,156";
   }
   set group(group){
      this.#group = group;
   }
   get group(){
      return this.#group;
   }
}

function isUint8Array(data) { return data instanceof Uint8Array }

function sanitize(args) {
   const data = args[0]
   if (isUint8Array(data) == false) return
   let offset = 0;
   // client_version (2 bytes) + random (32 bytes)
   if (Version.from(data).value < 0x0300) return Alert.fromAlertDescription(AlertDescription.PROTOCOL_VERSION)
   offset += 2 + 32;

   // session_id
   const sessionIdLen = data[offset];
   if (sessionIdLen > 32) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE)
   offset += 1 + sessionIdLen;

   // cipher_suites
   const _cipher = Cipher.from(data.subarray(offset));
   offset+=2

   // compression_methods
   if(data[offset]!==0) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE);
   offset+=1

   // extensions
   const extensionsLen = (data[offset] << 8) | data[offset + 1];
   const _extensions = parseItems(data, offset + 2, extensionsLen, Extension);
   offset += 2;

   args[0] = data.subarray(0, offset + extensionsLen);
   return
}

function parseExtension(extension, isHRR) {
   switch (extension.type) {
      case ExtensionType.KEY_SHARE: {
         extension.parser = isHRR ? KeyShareHelloRetryRequest : KeyShareServerHello; break;
      }
      case ExtensionType.SUPPORTED_VERSIONS: {
         extension.parser = Selected_version; break;
      }
      default:
         break;
   }
}

