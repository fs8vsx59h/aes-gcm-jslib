import * as AES from "./AES.ts";
import { assertEquals } from "jsr:@std/assert";

const ec = new TextEncoder();
const dc = new TextDecoder("utf-8");

const key = await AES.generateAesKey();
const keyJwk = await AES.exportKey(key);
const keyBack = await AES.importKey(keyJwk);

Deno.test("AES key export and import", () => {
    assertEquals(key, keyBack);
});

const iv = await AES.generateIV();
const ivBase64 = await AES.exportIV(iv);
const ivBack = await AES.importIV(ivBase64);

Deno.test("AES IV export and import", () => {
    assertEquals(iv, ivBack);
});

const plaintext = "Hello, world!";
const encoded = ec.encode(plaintext);
const encrypted = await AES.encrypt(key, iv, encoded);
const decrypted = await AES.decrypt(key, iv, new Uint8Array(encrypted));
const decoded = dc.decode(decrypted);

Deno.test("AES encryption and decryption", () => {
    assertEquals(decoded, plaintext);
});
