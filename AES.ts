const { subtle } = globalThis.crypto;
const crypto = globalThis.crypto;

async function generateAesKey(length = 256) {
    const key = await subtle.generateKey(
        {
            name: "AES-GCM",
            length,
        },
        true,
        ["encrypt", "decrypt"],
    );

    return key;
}

function generateIV() {
    const iv = crypto.getRandomValues(new Uint8Array(16));
    return iv;
}

function exportKey(key: CryptoKey) {
    return subtle.exportKey("jwk", key);
}

function importKey(keyJwk: JsonWebKey) {
    return subtle.importKey("jwk", keyJwk, "AES-GCM", true, [
        "encrypt",
        "decrypt",
    ]);
}

function exportIV(iv: Uint8Array) {
    const ivString = iv.toString();
    const ivStringBase64 = btoa(ivString);
    return ivStringBase64;
}

function importIV(ivStringBase64: string) {
    const ivString = atob(ivStringBase64);
    const iv = new Uint8Array(
        ivString.split(",").map((byte) => parseInt(byte, 10)),
    );
    return iv;
}

function encrypt(key: CryptoKey, iv: Uint8Array, data: Uint8Array) {
    const encrypted = subtle.encrypt({ name: "AES-GCM", iv }, key, data);
    return encrypted;
}

function decrypt(key: CryptoKey, iv: Uint8Array, data: Uint8Array) {
    const decrypted = subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return decrypted;
}

export {
    decrypt,
    encrypt,
    exportIV,
    exportKey,
    generateAesKey,
    generateIV,
    importIV,
    importKey,
};
