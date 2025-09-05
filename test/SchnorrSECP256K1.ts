import {expect} from "chai";
import {network} from "hardhat";

const {ethers} = await network.connect();
import {randomBytes} from "crypto";
// @ts-ignore
import * as secp from "@noble/secp256k1";

// --- helpers ---
const bytesToBigInt = (b: Uint8Array | Buffer): bigint => BigInt("0x" + Buffer.from(b).toString("hex"));
const toHex = (b: Uint8Array | Buffer): `0x${string}` => ("0x" + Buffer.from(b).toString("hex")) as `0x${string}`;

function challenge(Rcomp: Uint8Array, m: Uint8Array, publicKeyComp: Uint8Array): bigint {
    // Uncompress R and derive its Ethereum address like in the contract helper
    const R_uncomp = secp.Point.fromBytes(Rcomp).toBytes(false); // 65 bytes: 0x04||X||Y
    const xy = R_uncomp.slice(1); // drop 0x04, keep 64 bytes
    const R_hash = ethers.keccak256(toHex(xy));
    const R_addr = ethers.getAddress("0x" + R_hash.slice(26)); // last 20 bytes as address

    const parity: number = publicKeyComp[0] + 27 - 2; // 27 or 28
    const pxHex = toHex(publicKeyComp.slice(1, 33));
    const mHex = toHex(m);


    const pxBI = BigInt("0x" + Buffer.from(publicKeyComp.slice(1, 33)).toString("hex"));
    const { px: pxCanon, parity: vCanon } = canonicalizePxParity(pxBI, parity);

    // e = keccak256(px || parity || m || address(R)) via Solidity-packed Keccak
    const eHex = ethers.solidityPackedKeccak256(
        [ "bytes32", "uint8", "bytes32","address"],
        [  ethers.toBeHex(pxCanon, 32), vCanon, mHex,R_addr,]
    );
     return BigInt(eHex);
}

function sign(m: Uint8Array, x: Uint8Array) {
    const publicKey = secp.getPublicKey(x, true); // compressed (33 bytes)

    // k must be a valid scalar; regenerate until valid
    let k: Uint8Array;
    do {
        k = randomBytes(32);
    } while (!secp.utils.isValidSecretKey(k));

    const R = secp.getPublicKey(k, true); // compressed (33 bytes)

    const eBI = challenge(R, m, publicKey);
    const N = secp.Point.CURVE().n;
    const xBI = bytesToBigInt(x);
    const kBI = bytesToBigInt(k);

    // s = k + x*e (mod n)
    const sBI = ( (kBI % N) + N - ((xBI * (eBI % N)) % N) ) % N;

    return {R, s: sBI, e: eBI};
}
function canonicalizePxParity(pxBI: bigint, parity: number): { px: bigint; parity: number } {
    const Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    const HALF_Q = (Q >> 1n) + 1n;
    if (pxBI === 0n || pxBI >= Q) throw new Error("invalid px");
    if (pxBI >= HALF_Q) {
        return { px: Q - pxBI, parity: 55 - parity }; // 27 <-> 28
    }
    return { px: pxBI, parity };
}
describe("SchnorrSECP256K1", function () {
    it("verifySignature function", async function () {
        const schnorrContract = await ethers.deployContract("SchnorrSECP256K1");
        const deploymentBlockNumber = await ethers.provider.getBlockNumber();
        const Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
        const HALF_Q = (Q >> 1n) + 1n;
        // generate a valid private key
        let privKey: Uint8Array = randomBytes(32);
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
        } while (false);//P.x >= HALF_Q


        // message (32 bytes)
        const m = randomBytes(32);
        const sig = sign(m, privKey);


        const parity = publicKey[0] - 2 + 27; // 27 or 28
        const pxBI = bytesToBigInt(publicKey.slice(1, 33));
        const mBI = bytesToBigInt(m);


        const pxB32 = ethers.toBeHex(pxBI);
        const mB32 = ethers.toBeHex(mBI);
        const sB32 = ethers.toBeHex(sig.s);

        const R_uncomp = secp.Point.fromBytes(sig.R).toBytes(false); // 65 bytes: 0x04||X||Y
        const xy = R_uncomp.slice(1); // drop 0x04, keep 64 bytes
        const R_hash = ethers.keccak256(toHex(xy));
        const R_addr = ethers.getAddress("0x" + R_hash.slice(26)); // last 20 bytes as address


        const ret = await schnorrContract.measureVerify.staticCall(pxB32,parity, sB32, mB32, R_addr);
        const cold = ret[0];
        const warm = ret[1];
        console.log("verify gas (cold):", cold.toString());
        console.log("verify gas (warm):", warm.toString());

        expect(
            await schnorrContract.verifySignature(pxB32,parity, sB32, mB32, R_addr )
        ).to.equal(true);
    });
});
