/**
 * @agi-gateway/xcp — XCP client and protocol primitives.
 *
 * The protocol functions are held to `sdk/vectors/*.json`, the same vectors
 * the Python implementation is held to. Run `npm test` to check this port.
 */
export * from "./protocol.mjs";
export { XCPClient, XCPError } from "./client.mjs";
