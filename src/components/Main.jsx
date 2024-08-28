import { bech32m } from "bech32";
import bls from "chia-bls";
import { useState } from "react";

const { AugSchemeMPL, JacobianPoint } = bls;

export default function Main() {
  const [m, setM] = useState("");

  const trimmed = m.trim();
  const result = trimmed.length > 0 ? calc(trimmed) : null;

  return (
    <>
      <h1 style={{ fontSize: 40 }}>BLS Public Key Encoder</h1>
      <input value={m} onChange={(e) => setM(e.target.value)}></input>
      <p style={{ width: 700, wordWrap: "break-word" }}>
        {m.trim().length > 0
          ? result ?? "Invalid master public key"
          : "Enter your master public key"}
      </p>
      <p style={{ fontSize: 20 }}>
        This converts a master public key to the first derivation encoded with
        the bls12381 prefix.
      </p>
    </>
  );
}

function calc(hex) {
  try {
    const key = JacobianPoint.fromHexG1(hex.replace("0x", ""));
    const address = toAddress(
      AugSchemeMPL.deriveChildPkUnhardened(key, 0).toBytes(),
      "bls1238"
    );
    return address;
  } catch (e) {
    console.error(e);
    return null;
  }
}

function toAddress(hash, prefix) {
  return bech32m.encode(prefix, convertBits(hash, 8, 5, true), Infinity);
}

function addressInfo(address) {
  const { words, prefix } = bech32m.decode(address);
  return {
    hash: convertBits(Uint8Array.from(words), 5, 8, false),
    prefix,
  };
}

function convertBits(bytes, from, to, pad) {
  let accumulate = 0;
  let bits = 0;
  let maxv = (1 << to) - 1;
  let result = [];
  for (const value of bytes) {
    const b = value & 0xff;
    if (b < 0 || b >> from > 0) throw new Error("Could not convert bits.");
    accumulate = (accumulate << from) | b;
    bits += from;
    while (bits >= to) {
      bits -= to;
      result.push((accumulate >> bits) & maxv);
    }
  }
  if (pad && bits > 0) {
    result.push((accumulate << (to - bits)) & maxv);
  } else if (bits >= from || ((accumulate << (to - bits)) & maxv) !== 0) {
    throw new Error("Could not convert bits.");
  }
  return Uint8Array.from(result);
}
