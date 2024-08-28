import { bech32m } from "bech32";
import bls from "chia-bls";
import clvm from "clvm-lib";
import { useState } from "react";

const { AugSchemeMPL, JacobianPoint, PrivateKey, bigIntToBytes, hash256 } = bls;
const { Program } = clvm;

export default function Main() {
  const [m, setM] = useState("");

  const trimmed = m.trim();
  const result = trimmed.length > 0 ? calc(trimmed) : null;

  return (
    <div style={{ maxWidth: 600, margin: "auto", textAlign: "center" }}>
      <h1 style={{ fontSize: 40 }}>BLS Public Key Encoder</h1>
      <textarea
        style={{
          width: "500px",
          height: "74px",
          fontSize: 22,
          padding: "10px",
          appearance: "none",
          outline: "none",
          border: "1px solid black",
          borderRadius: "6px",
          fontFamily: "Arial",
        }}
        placeholder="Enter your master public key"
        value={m}
        onChange={(e) => setM(e.target.value)}
      ></textarea>
      <p style={{ fontSize: 22, wordWrap: "break-word" }}>
        {m.trim().length > 0 ? result ?? "Invalid key format" : ""}
      </p>
      <p style={{ fontSize: 18 }}>
        This converts a master public key to the first wallet address encoded
        with the "bls1238" prefix.
      </p>
    </div>
  );
}

function pathInto(pk, nums) {
  for (const num of nums) {
    pk = AugSchemeMPL.deriveChildPkUnhardened(pk, num);
  }
  return pk;
}

const groupOrder =
  0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

const defaultHidden = Program.deserializeHex("ff0980").hash();

export function calculateSyntheticPublicKey(publicKey, hiddenPuzzleHash) {
  return JacobianPoint.fromBytes(
    Program.deserializeHex("ff1dff02ffff1effff0bff02ff05808080").run(
      Program.fromList([
        Program.fromJacobianPoint(publicKey),
        Program.fromBytes(hiddenPuzzleHash),
      ])
    ).value.atom,
    false
  );
}

export function calculateSyntheticPrivateKey(privateKey, hiddenPuzzleHash) {
  const privateExponent = bytesToBigInt(privateKey.toBytes(), "big");
  const publicKey = privateKey.getG1();
  const syntheticOffset = calculateSyntheticOffset(publicKey, hiddenPuzzleHash);
  const syntheticPrivateExponent = mod(
    privateExponent + syntheticOffset,
    groupOrder
  );
  const blob = bigIntToBytes(syntheticPrivateExponent, 32, "big");
  return PrivateKey.fromBytes(blob);
}

export function calculateSyntheticOffset(publicKey, hiddenPuzzleHash) {
  const blob = hash256(concatBytes(publicKey.toBytes(), hiddenPuzzleHash));
  return mod(decodeBigInt(blob), groupOrder);
}

function calc(hex) {
  try {
    const key = JacobianPoint.fromHexG1(hex.replace("0x", ""));
    const address = toAddress(
      Program.deserializeHex(
        "ff02ffff01ff02ffff03ff0bffff01ff02ffff03ffff09ff05ffff1dff0bffff1effff0bff0bffff02ff06ffff04ff02ffff04ff17ff8080808080808080ffff01ff02ff17ff2f80ffff01ff088080ff0180ffff01ff04ffff04ff04ffff04ff05ffff04ffff02ff06ffff04ff02ffff04ff17ff80808080ff80808080ffff02ff17ff2f808080ff0180ffff04ffff01ff32ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff06ffff04ff02ffff04ff09ff80808080ffff02ff06ffff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff018080"
      )
        .curry([
          Program.fromJacobianPoint(
            calculateSyntheticPublicKey(
              pathInto(key, [12381, 8444, 2, 0]),
              defaultHidden
            )
          ),
        ])
        .hash(),
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
