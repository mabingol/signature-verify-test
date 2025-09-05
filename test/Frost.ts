import {expect} from "chai";
import {network} from "hardhat";

const {ethers} = await network.connect();
import { createHash,randomBytes } from "crypto";

 // @ts-ignore
import * as secp from "@noble/secp256k1";
import {zeroPadValue} from "ethers";
import { sha256 } from "@noble/hashes/sha256";

// --- helpers ---
const bytesToBigInt = (b: Uint8Array | Buffer): bigint => BigInt("0x" + Buffer.from(b).toString("hex"));
const toHex = (b: Uint8Array | Buffer): `0x${string}` => ("0x" + Buffer.from(b).toString("hex")) as `0x${string}`;
const Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const HALF_Q = (Q >> 1n) + 1n;

describe("Frost", function () {
    it("verify function", async function () {
        const frostContract = await ethers.deployContract("Frost");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();


        // generate a valid private key
        let privKey: Uint8Array
         = randomBytes(32);

        let publicKey = secp.getPublicKey(privKey, true);
        let P = secp.Point.fromBytes(publicKey);

        do {
            privKey = randomBytes(32);
            publicKey = secp.getPublicKey(privKey, true);
            P = secp.Point.fromBytes(publicKey);
            if (!secp.utils.isValidSecretKey((privKey)))
            {
                console.log(   "problem with key");
                continue;
            }
        } while (P.x >= HALF_Q);

        // message (32 bytes)
        const message = randomBytes(32);
        const message32 = zeroPadValue(("0x"+Buffer.from(message).toString("hex")) as `0x${string}`, 32) as `0x${string}`;
        const sig = sign(message32, privKey);

        let R = secp.Point.fromBytes(sig.R);


        const px = ethers.toBeHex(P.x);
        const py = ethers.toBeHex(P.y);
        const rx = ethers.toBeHex(R.x);
        const ry = ethers.toBeHex(R.y);
        const z = ethers.toBeHex(sig.s);

        console.log("msg\t=",message32);
        console.log("px\t=",px);
        console.log("py\t=",py);
        console.log("rx\t=",rx);
        console.log("ry\t=",ry);
        console.log("z\t=",z);

        // Compute expected address like the inline assembly in Solidity:
        // keccak256(px || py)[12:]
        const packed = ethers.concat([
            ethers.zeroPadValue(px, 32),
            ethers.zeroPadValue(py, 32),
        ]);
        const hash = ethers.keccak256(packed);
        const addr = ethers.getAddress("0x" + hash.slice(26)); // take last 20 bytes

        console.log("addr\t=",addr);

        const ret = await frostContract.measureVerify.staticCall(message32, px, py, rx, ry, z);
        const cold = ret[0];
        const warm = ret[1];
        console.log("verify gas (cold):", cold.toString());
        console.log("verify gas (warm):", warm.toString());

        // Call verify
        const result = await frostContract.verify(message32, px, py, rx, ry, z);

        expect(result).to.equal(addr);
    });
   /* it("verify function 2", async function () {
        const frostContract = await ethers.deployContract("Frost");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();

        const message =
            "0x4141414141414141414141414141414141414141414141414141414141414141";

        const px =
            "0x4F6340CFDD930A6F54E730188E3071D150877FA664945FB6F120C18B56CE1C09";
        const py =
            "0x802A5E67C00A70D85B9A088EAC7CF5B9FB46AC5C0B2BD7D1E189FAC210F6B7EF";

        const rx =
            "0x501DCFE29D881AA855BF25979BD79F751AA9536AF7A389403CD345B02D1E6F25";
        const ry =
            "0x839AD3B762F50FE560F4688A15A1CAED522919F33928567F95BC48CBD9B8C771";

        const z =
            "0x4FDEA9858F3E6484F1F0D64E7C17879C25F68DA8BD0E82B063CF7410DDF5A886";

        // Compute expected address like the inline assembly in Solidity:
        // keccak256(px || py)[12:]
        const packed = ethers.concat([
            ethers.zeroPadValue(px, 32),
            ethers.zeroPadValue(py, 32),
        ]);
        const hash = ethers.keccak256(packed);
        const addr = ethers.getAddress("0x" + hash.slice(26)); // take last 20 bytes

        console.log(addr);

        const ret = await frostContract.measureVerify.staticCall(message, px, py, rx, ry, z);
        const cold = ret[0];
        const warm = ret[1];
        console.log("verify gas (cold):", cold.toString());
        console.log("verify gas (warm):", warm.toString());

        // Call verify
        const result = await frostContract.verify(message, px, py, rx, ry, z);

        expect(result).to.equal(addr);
    });*/
});

/** Domain separator exactly as in Solidity */
const DOMAIN = "FROST-secp256k1-SHA256-v1chal";

/** Ensure a value is a 0x-prefixed hex string of length <= 32 bytes, then left-pad to 32 bytes. */
/** Ensure a value is exactly 32 bytes (left-padded). Returns hex string. */
function toBytes32(value: string | bigint): `0x${string}` {
    if (typeof value === "bigint") {
        // safe: pads/truncates to 32 bytes and guarantees even-length hex
        return ethers.toBeHex(value, 32) as `0x${string}`;
    } else {
        if (!value.startsWith("0x")) {
            throw new Error(`hex string must start with 0x, got: ${value}`);
        }
        let hex = value;
        // make even-length (ethers requires even number of nibbles)
        if (((hex.length - 2) % 2) === 1) {
            hex = ("0x0" + hex.slice(2)) as `0x${string}`;
        }
        // pad to 32 bytes
        return ethers.zeroPadValue(hex, 32) as `0x${string}`;
    }
}


const prefix = (y: bigint) => (y & 1n) === 1n ? 0x03 : 0x02;

// preimage: [comp(R) | comp(P) | message32]
function _preimage(rx: bigint, ry: bigint, px: bigint, py: bigint, message32: string): Uint8Array {
    const r = new Uint8Array(33);
    r[0] = prefix(ry);
    r.set(Buffer.from(toBytes32(rx).slice(2), "hex"), 1);

    const p = new Uint8Array(33);
    p[0] = prefix(py);
    p.set(Buffer.from(toBytes32(px).slice(2), "hex"), 1);

    const m = Buffer.from(message32.slice(2), "hex");
    return new Uint8Array([...r, ...p, ...m]);
}



// e = H(preimage || domain) mod Q (Solidity _challenge)
function challenge(rx: bigint, ry: bigint, px: bigint, py: bigint, message32: string): bigint {
    const pre = _preimage(rx, ry, px, py, message32);
    // FROST(secp256k1, SHA-256) uses expand_message_xmd with SHA-256 to 48 bytes,
    // then interprets those 48 bytes as a big-endian integer reduced mod n (_N).
    const uniform = expandMessageXmd(pre, Buffer.from(DOMAIN, "utf8"), 48);
    return bytesToBigInt(uniform) % Q;
}
function expandMessageXmd(msg: Uint8Array, DST: Uint8Array, len: number): Uint8Array {
    // RFC 9380 §5.3.1 XMD for SHA-256
    // H = SHA-256, b_out = 32, blockLen = 64
    const H = (data: Uint8Array) => sha256.create().update(data).digest(); // 32 bytes
    const OUTLEN = 32;       // digest size for SHA-256
    const BLOCKLEN = 64;     // block size for SHA-256

    const ell = Math.ceil(len / OUTLEN);
    if (ell > 255) throw new Error("expand too large");

    // DST' = DST || I2OSP(len(DST), 1)
    const DSTPrime = new Uint8Array([...DST, DST.length & 0xff]);

    // Z_pad is BLOCKLEN zeros (not OUTLEN!)
    const Zpad = new Uint8Array(BLOCKLEN);

    // l_i_b_str = I2OSP(len, 2)
    const lIBStr = new Uint8Array([(len >> 8) & 0xff, len & 0xff]);

    // b0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST')
    const b0 = H(new Uint8Array([...Zpad, ...msg, ...lIBStr, 0x00, ...DSTPrime]));

    // b1 = H(b0 || 0x01 || DST')
    const b: Uint8Array[] = new Array(ell);
    b[0] = H(new Uint8Array([...b0, 0x01, ...DSTPrime]));

    // for i in 2..ell: bi = H((b0 XOR b_{i-1}) || I2OSP(i,1) || DST')
    for (let i = 1; i < ell; i++) {
        const t = new Uint8Array(OUTLEN);
        for (let j = 0; j < OUTLEN; j++) t[j] = b0[j] ^ b[i - 1][j];
        b[i] = H(new Uint8Array([...t, (i + 1) & 0xff, ...DSTPrime]));
    }

    // concatenate and truncate to len
    const out = new Uint8Array(ell * OUTLEN);
    for (let i = 0; i < ell; i++) out.set(b[i], i * OUTLEN);
    return out.slice(0, len);
}

function sign(m: string, x: Uint8Array) {
    const publicKey = secp.getPublicKey(x, true); // 33B compressed
    const P = secp.Point.fromBytes(publicKey);
    const n = secp.Point.CURVE().n;
    const xBI = bytesToBigInt(x);

    let s: bigint;
    let R: Uint8Array;
    let Rpoint: any;
    let kBI: bigint;

    // Loop until we get a nonzero s that passes scalar check
    do {
        // 1) Pick a valid nonce k
        let k: Uint8Array;
        do { k = randomBytes(32); } while (!secp.utils.isValidSecretKey(k));
        kBI = bytesToBigInt(k);

        // 2) R = k*G (compressed)
        R = secp.getPublicKey(k, true);
        Rpoint = secp.Point.fromBytes(R);

        // 3) Force even-Y: if R.y is odd, flip k -> n - k and recompute R
        if ((Rpoint.y & 1n) === 1n) {
            kBI = (n - kBI) % n;
            const kBytes = ethers.zeroPadValue("0x" + kBI.toString(16), 32);
            R = secp.getPublicKey(ethers.getBytes(kBytes), true);
            Rpoint = secp.Point.fromBytes(R);
        }

        // 4) e = H2(R, P, m) using the XMD construction to 48 bytes, mod n
        const e = challenge(Rpoint.x, Rpoint.y, P.x, P.y, m) % n;

        // 5) s = k + x*e (mod n)
        s = (kBI + (xBI * e) % n) % n;

        // Repeat if s == 0 (invalid per _isScalar in the verifier)
    } while (s === 0n);

    return { R, s };
}
