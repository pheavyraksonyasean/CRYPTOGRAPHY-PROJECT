// Utility functions for base64 encoding/decoding
function arrayBufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const len = binaryString.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

let aesKeyGlobal = null;

// Generate AES key and export to Base64
async function generateAESKey() {
  aesKeyGlobal = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );

  const exported = await crypto.subtle.exportKey("raw", aesKeyGlobal);
  document.getElementById("aesKey").value = arrayBufferToBase64(exported);
}

// Encrypt plain text using AES-GCM
async function encrypt() {
  const plainText = document.getElementById("plainText").value;
  const keyBase64 = document.getElementById("aesKey").value;

  if (!plainText || !keyBase64) {
    alert("Please enter both plain text and generate the AES key.");
    return;
  }

  const keyBuffer = base64ToArrayBuffer(keyBase64);
  const key = await crypto.subtle.importKey(
    "raw",
    keyBuffer,
    "AES-GCM",
    false,
    ["encrypt"]
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(plainText);

  const cipherBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encodedText
  );

  const result = {
    iv: arrayBufferToBase64(iv),
    data: arrayBufferToBase64(cipherBuffer),
  };

  document.getElementById("cipherOutput").value = JSON.stringify(result);
}

// Decrypt AES-GCM encrypted text
async function decrypt() {
  const cipherInput = document.getElementById("cipherInput").value;
  const keyBase64 = document.getElementById("decryptKey").value;

  if (!cipherInput || !keyBase64) {
    alert("Please enter both cipher text and AES key.");
    return;
  }

  try {
    const { iv, data } = JSON.parse(cipherInput);
    const ivBuffer = base64ToArrayBuffer(iv);
    const dataBuffer = base64ToArrayBuffer(data);
    const keyBuffer = base64ToArrayBuffer(keyBase64);

    const key = await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      "AES-GCM",
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: ivBuffer },
      key,
      dataBuffer
    );

    document.getElementById("plainOutput").value = new TextDecoder().decode(decrypted);
  } catch (e) {
    alert("Decryption failed. Check the key or data format.");
    document.getElementById("plainOutput").value = "";
  }
}
