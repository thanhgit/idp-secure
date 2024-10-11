import { createDecipheriv } from "crypto";
import type { SOPS } from "./sops-file";
import get from 'lodash-es/get';
import cloneDeep from 'lodash-es/cloneDeep';

import { decryptAgeEncryptionKey, getPublicAgeKey } from "./age";

async function getSopsEncryptionKeyForRecipient(sops: SOPS, secretKey: string) {
  const pubKey = await getPublicAgeKey(secretKey);

  const recipient = sops.sops.age.find((config) => config.recipient === pubKey);
  if (!recipient) {
    throw new Error("no matching recipient found in age config");
  }

  return decryptAgeEncryptionKey(recipient.enc, secretKey);
}

function decryptValue(
  value: string,
  decryptionKey: Buffer,
  aad = "",
): Buffer | boolean | number | string {
  const match = value.match(
    /^ENC\[AES256_GCM,data:(.+),iv:(.+),tag:(.+),type:(.+)\]/,
  );
  if (!match) {
    return value;
  }

  const [, encValue, ivBase64, tagBase64, dataType] = match;
  if (!encValue || !ivBase64 || !tagBase64) {
    throw new Error("Invalid ENC format");
  }

  const iv = Buffer.from(ivBase64, "base64");
  const tag = Buffer.from(tagBase64, "base64");

  const decipher = createDecipheriv("aes-256-gcm", decryptionKey, iv);
  decipher.setAuthTag(tag);
  decipher.setAAD(Buffer.from(aad));
  const decrypted = decipher.update(encValue, "base64", "utf8");

  switch (dataType) {
    case "bytes":
      return Buffer.from(decrypted, "utf8");
    case "str":
      return decrypted;
    case "int":
      return parseInt(decrypted, 10);
    case "float":
      return parseFloat(decrypted);
    case "bool":
      return decrypted.toLowerCase() === "true";
    default:
      throw new Error(`Unknown type ${dataType}`);
  }
}

function decryptObject(obj: any, decryptionKey: Buffer) {
  if (typeof obj !== "object" || obj === null) {
    return obj;
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
  for (const key of Object.keys(obj)) {
    const value = obj[key];
    if (typeof value === "string" && value.startsWith("ENC[AES256_GCM,data:")) {
      obj[key] = decryptValue(value, decryptionKey);
    } else if (typeof value === "object") {
      // Recursively decrypt objects and arrays
      obj[key] = decryptObject(value, decryptionKey);
    }
  }

  return obj;
}

export async function decrypt(sops: SOPS, secretKey: string, keyPath?: string) {
  const decryptionKey = await getSopsEncryptionKeyForRecipient(sops, secretKey);

  // If we have a path to a specific key, only decrypt that
  if (keyPath) {
    const value = get(sops, keyPath);
    if (typeof value !== "string") {
      throw new Error(`Unable to get sops value at ${keyPath}`);
    }

    return decryptValue(value, decryptionKey);
  }

  // Otherwise, decrypt the whole thing, stripping out the sops metadata
  // and only use the rest of the keys
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { sops: _, ...data } = sops;
  // Deep clone the object so we can decrypt in-place:
  const cloned = cloneDeep(data);
  const decryptedData = decryptObject(cloned, decryptionKey);

  if (sops.sops.mac && sops.sops.lastmodified) {
    // TODO: decrypt mac and compare to hash of all values.
    //
    // Message Authentication Code - https://github.com/getsops/sops/?tab=readme-ov-file#message-authentication-code
    //
    // In addition to authenticating branches of the tree using keys
    // as additional data, SOPS computes a MAC on all the values to
    // ensure that no value has been added or removed fraudulently.
    // The MAC is stored encrypted with AES_GCM and the data key
    // under tree -> sops -> mac. This behavior can be modified
    // using --mac-only-encrypted flag or .sops.yaml config file
    // which makes SOPS compute a MAC only over values it encrypted
    // and not all values.
  }

  return decryptedData;
}
