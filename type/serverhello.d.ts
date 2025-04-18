import { Version, Cipher, Extension } from "../src/dep.ts"

/**
 * Represents a parsed TLS ServerHello message.
 * Extends `Uint8Array` to allow for binary manipulation directly.
 * @version 0.0.4
 */
export class ServerHello extends Uint8Array {
  /** @internal */
  static from: typeof ServerHello.create;

  /**
   * Create a new ServerHello instance from raw bytes or arguments.
   * @param args Arguments passed to the `Uint8Array` constructor.
   * @returns A `ServerHello` instance.
   */
  static create(...args: ConstructorParameters<typeof Uint8Array>): ServerHello;

  constructor(...args: ConstructorParameters<typeof Uint8Array>);

  /**
   * The TLS version field (always 0x0303 for TLS 1.2).
   */
  get version(): Version;

  /**
   * The 32-byte random value sent by the server.
   */
  get random(): Uint8Array;

  /**
   * The session ID echoed by the server (variable length).
   */
  get legacy_session_id(): Uint8Array & { end: number };

  /**
   * The cipher suite selected by the server.
   */
  get cipher(): Cipher & { end: number };

  /**
   * The legacy compression method (usually 0x00).
   */
  get legacy_compression_methods(): Uint8Array & { end: number };

  /**
   * A map of extension type to parsed `Extension` objects.
   */
  get extensions(): Map<number, Extension>;

  /**
   * A structured TLS handshake message wrapping this ServerHello.
   */
  get handshake(): Uint8Array & {
    group: any;
    cipher: Cipher;
    message: ServerHello;
  };

  /**
   * A full TLS record layer message wrapping the handshake.
   */
  get record(): Uint8Array & {
    fragment: Uint8Array;
    group: any;
    cipher: Cipher;
  };

  /**
   * Returns `true` if this ServerHello is a HelloRetryRequest (HRR).
   */
  get isHRR(): boolean;

  /**
   * Sets the group used in key exchange.
   */
  set group(value: any);

  /**
   * Gets the group used in key exchange.
   */
  get group(): any;
}
