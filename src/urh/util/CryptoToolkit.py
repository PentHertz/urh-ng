"""
Automotive RF Crypto Toolkit for URH.

Implements ciphers and protocol decoders used in car key fobs,
gate remotes, and other rolling code systems. Based on
Flipper-ARF and ProtoPirate implementations.

Supported ciphers / protocol decoders:
- TEA — PSA Peugeot/Citroen, VAG VW/Audi (Types 2/4)
- AES-128 — KIA V6, Hyundai, Beninca ARC
- AUT64 — VAG VW/Audi (Types 1/3, older models)
- KIA V5 Mixer — KIA V5 (18-round XOR)
- Mitsubishi V0 XOR — counter-dependent XOR + NOT
- Ford V0 — XOR obfuscation + bit interleave + GF(2) CRC
- Nice Flor-S — rainbow table + XOR deobfuscation
- Somfy Telis/Keytis — rolling XOR shift
- Came Atomo — XOR cipher + bit shifting
- Came Twee — XOR rainbow table
- Scher-Khan — Pi-derived XOR table + bit shuffle
- Phoenix V2 — 16-iteration XOR bit-shuffle
- Porsche Cayenne — 24-bit rotating register cipher
- Subaru — rotating register XOR
- Mazda Siemens — parity-selected XOR mask
- Security+ v1/v2 — ternary encoding (LiftMaster/Chamberlain)
- PSA TEA brute-force (0x23 XOR / 0x36 TEA modes)
- KIA V3/V4 KeeLoq — known master key
- FAAC SLH — KeeLoq FAAC learning mode
"""


# ═══════════════════════════════════════════════════════════
# TEA (Tiny Encryption Algorithm)
# Used by: PSA Peugeot/Citroen, VAG VW/Audi
# Key: 128 bits (4x 32-bit), Block: 64 bits (2x 32-bit)
# ═══════════════════════════════════════════════════════════

TEA_DELTA = 0x9E3779B9
TEA_ROUNDS = 32
MASK32 = 0xFFFFFFFF


def tea_encrypt(v0, v1, key):
    """
    TEA encrypt.

    Args:
        v0, v1: two 32-bit halves of the 64-bit plaintext
        key: list/tuple of 4 x 32-bit key words [k0, k1, k2, k3]

    Returns:
        (v0, v1) encrypted
    """
    s = 0
    for _ in range(TEA_ROUNDS):
        s = (s + TEA_DELTA) & MASK32
        v0 = (v0 + (((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1]))) & MASK32
        v1 = (v1 + (((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3]))) & MASK32
    return v0, v1


def tea_decrypt(v0, v1, key):
    """
    TEA decrypt.

    Args:
        v0, v1: two 32-bit halves of the 64-bit ciphertext
        key: list/tuple of 4 x 32-bit key words [k0, k1, k2, k3]

    Returns:
        (v0, v1) decrypted
    """
    s = (TEA_DELTA * TEA_ROUNDS) & MASK32
    for _ in range(TEA_ROUNDS):
        v1 = (v1 - (((v0 << 4) + key[2]) ^ (v0 + s) ^ ((v0 >> 5) + key[3]))) & MASK32
        v0 = (v0 - (((v1 << 4) + key[0]) ^ (v1 + s) ^ ((v1 >> 5) + key[1]))) & MASK32
        s = (s - TEA_DELTA) & MASK32
    return v0, v1


# Known TEA keys
VAG_TEA_KEY = [0x0B46502D, 0x5E253718, 0x2BF93A19, 0x622C1206]


# ═══════════════════════════════════════════════════════════
# AES-128
# Used by: KIA V6 / Hyundai
# Key: 128 bits, Block: 128 bits, Rounds: 10
# ═══════════════════════════════════════════════════════════

AES_SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

AES_SBOX_INV = [
    0x52,
    0x09,
    0x6A,
    0xD5,
    0x30,
    0x36,
    0xA5,
    0x38,
    0xBF,
    0x40,
    0xA3,
    0x9E,
    0x81,
    0xF3,
    0xD7,
    0xFB,
    0x7C,
    0xE3,
    0x39,
    0x82,
    0x9B,
    0x2F,
    0xFF,
    0x87,
    0x34,
    0x8E,
    0x43,
    0x44,
    0xC4,
    0xDE,
    0xE9,
    0xCB,
    0x54,
    0x7B,
    0x94,
    0x32,
    0xA6,
    0xC2,
    0x23,
    0x3D,
    0xEE,
    0x4C,
    0x95,
    0x0B,
    0x42,
    0xFA,
    0xC3,
    0x4E,
    0x08,
    0x2E,
    0xA1,
    0x66,
    0x28,
    0xD9,
    0x24,
    0xB2,
    0x76,
    0x5B,
    0xA2,
    0x49,
    0x6D,
    0x8B,
    0xD1,
    0x25,
    0x72,
    0xF8,
    0xF6,
    0x64,
    0x86,
    0x68,
    0x98,
    0x16,
    0xD4,
    0xA4,
    0x5C,
    0xCC,
    0x5D,
    0x65,
    0xB6,
    0x92,
    0x6C,
    0x70,
    0x48,
    0x50,
    0xFD,
    0xED,
    0xB9,
    0xDA,
    0x5E,
    0x15,
    0x46,
    0x57,
    0xA7,
    0x8D,
    0x9D,
    0x84,
    0x90,
    0xD8,
    0xAB,
    0x00,
    0x8C,
    0xBC,
    0xD3,
    0x0A,
    0xF7,
    0xE4,
    0x58,
    0x05,
    0xB8,
    0xB3,
    0x45,
    0x06,
    0xD0,
    0x2C,
    0x1E,
    0x8F,
    0xCA,
    0x3F,
    0x0F,
    0x02,
    0xC1,
    0xAF,
    0xBD,
    0x03,
    0x01,
    0x13,
    0x8A,
    0x6B,
    0x3A,
    0x91,
    0x11,
    0x41,
    0x4F,
    0x67,
    0xDC,
    0xEA,
    0x97,
    0xF2,
    0xCF,
    0xCE,
    0xF0,
    0xB4,
    0xE6,
    0x73,
    0x96,
    0xAC,
    0x74,
    0x22,
    0xE7,
    0xAD,
    0x35,
    0x85,
    0xE2,
    0xF9,
    0x37,
    0xE8,
    0x1C,
    0x75,
    0xDF,
    0x6E,
    0x47,
    0xF1,
    0x1A,
    0x71,
    0x1D,
    0x29,
    0xC5,
    0x89,
    0x6F,
    0xB7,
    0x62,
    0x0E,
    0xAA,
    0x18,
    0xBE,
    0x1B,
    0xFC,
    0x56,
    0x3E,
    0x4B,
    0xC6,
    0xD2,
    0x79,
    0x20,
    0x9A,
    0xDB,
    0xC0,
    0xFE,
    0x78,
    0xCD,
    0x5A,
    0xF4,
    0x1F,
    0xDD,
    0xA8,
    0x33,
    0x88,
    0x07,
    0xC7,
    0x31,
    0xB1,
    0x12,
    0x10,
    0x59,
    0x27,
    0x80,
    0xEC,
    0x5F,
    0x60,
    0x51,
    0x7F,
    0xA9,
    0x19,
    0xB5,
    0x4A,
    0x0D,
    0x2D,
    0xE5,
    0x7A,
    0x9F,
    0x93,
    0xC9,
    0x9C,
    0xEF,
    0xA0,
    0xE0,
    0x3B,
    0x4D,
    0xAE,
    0x2A,
    0xF5,
    0xB0,
    0xC8,
    0xEB,
    0xBB,
    0x3C,
    0x83,
    0x53,
    0x99,
    0x61,
    0x17,
    0x2B,
    0x04,
    0x7E,
    0xBA,
    0x77,
    0xD6,
    0x26,
    0xE1,
    0x69,
    0x14,
    0x63,
    0x55,
    0x21,
    0x0C,
    0x7D,
]

AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _aes_xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _aes_mix_col(r):
    a = [0] * 4
    b = [0] * 4
    for c in range(4):
        a[c] = r[c]
        b[c] = _aes_xtime(r[c])
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1]
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2]
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3]
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0]


def aes128_encrypt(plaintext, key):
    """
    AES-128 encrypt a 16-byte block.

    Args:
        plaintext: list of 16 bytes
        key: list of 16 bytes

    Returns:
        list of 16 encrypted bytes
    """
    # Key expansion
    rk = list(key) + [0] * 160
    for i in range(4, 44):
        t = rk[(i - 1) * 4 : i * 4]
        if i % 4 == 0:
            t = [
                AES_SBOX[t[1]] ^ AES_RCON[i // 4 - 1],
                AES_SBOX[t[2]],
                AES_SBOX[t[3]],
                AES_SBOX[t[0]],
            ]
        for j in range(4):
            rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j]

    state = list(plaintext)

    # AddRoundKey
    for i in range(16):
        state[i] ^= rk[i]

    for rnd in range(1, 11):
        # SubBytes
        state = [AES_SBOX[b] for b in state]
        # ShiftRows
        state[1], state[5], state[9], state[13] = (
            state[5],
            state[9],
            state[13],
            state[1],
        )
        state[2], state[6], state[10], state[14] = (
            state[10],
            state[14],
            state[2],
            state[6],
        )
        state[3], state[7], state[11], state[15] = (
            state[15],
            state[3],
            state[7],
            state[11],
        )
        # MixColumns (not in last round)
        if rnd < 10:
            for c in range(4):
                col = state[c * 4 : c * 4 + 4]
                _aes_mix_col(col)
                state[c * 4 : c * 4 + 4] = col
        # AddRoundKey
        off = rnd * 16
        for i in range(16):
            state[i] ^= rk[off + i]

    return state


def aes128_decrypt(ciphertext, key):
    """
    AES-128 decrypt a 16-byte block.

    Args:
        ciphertext: list of 16 bytes
        key: list of 16 bytes

    Returns:
        list of 16 decrypted bytes
    """
    # Key expansion (same as encrypt)
    rk = list(key) + [0] * 160
    for i in range(4, 44):
        t = rk[(i - 1) * 4 : i * 4]
        if i % 4 == 0:
            t = [
                AES_SBOX[t[1]] ^ AES_RCON[i // 4 - 1],
                AES_SBOX[t[2]],
                AES_SBOX[t[3]],
                AES_SBOX[t[0]],
            ]
        for j in range(4):
            rk[i * 4 + j] = rk[(i - 4) * 4 + j] ^ t[j]

    state = list(ciphertext)

    # AddRoundKey (last round key)
    for i in range(16):
        state[i] ^= rk[160 + i]

    for rnd in range(9, -1, -1):
        # InvShiftRows
        state[1], state[5], state[9], state[13] = (
            state[13],
            state[1],
            state[5],
            state[9],
        )
        state[2], state[6], state[10], state[14] = (
            state[10],
            state[14],
            state[2],
            state[6],
        )
        state[3], state[7], state[11], state[15] = (
            state[7],
            state[11],
            state[15],
            state[3],
        )
        # InvSubBytes
        state = [AES_SBOX_INV[b] for b in state]
        # AddRoundKey
        off = rnd * 16
        for i in range(16):
            state[i] ^= rk[off + i]
        # InvMixColumns (not in first round)
        if rnd > 0:
            for c in range(4):
                col = state[c * 4 : c * 4 + 4]
                # Inverse mix using repeated xtime
                u = _aes_xtime(_aes_xtime(col[0] ^ col[2]))
                v = _aes_xtime(_aes_xtime(col[1] ^ col[3]))
                col[0] ^= u
                col[1] ^= v
                col[2] ^= u
                col[3] ^= v
                _aes_mix_col(col)
                state[c * 4 : c * 4 + 4] = col

    return state


# ═══════════════════════════════════════════════════════════
# AUT64 Block Cipher
# Used by: VAG VW/Audi (older models)
# Key: 64 bits, Block: 64 bits, Rounds: 12
# ═══════════════════════════════════════════════════════════

AUT64_ROUNDS = 12

# GF(2^4) multiplication table (16x16 = 256 entries)
_AUT64_TABLE_OFFSET = [
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0,
    0x1,
    0x2,
    0x3,
    0x4,
    0x5,
    0x6,
    0x7,
    0x8,
    0x9,
    0xA,
    0xB,
    0xC,
    0xD,
    0xE,
    0xF,
    0x0,
    0x2,
    0x4,
    0x6,
    0x8,
    0xA,
    0xC,
    0xE,
    0x3,
    0x1,
    0x7,
    0x5,
    0xB,
    0x9,
    0xF,
    0xD,
    0x0,
    0x3,
    0x6,
    0x5,
    0xC,
    0xF,
    0xA,
    0x9,
    0xB,
    0x8,
    0xD,
    0xE,
    0x7,
    0x4,
    0x1,
    0x2,
    0x0,
    0x4,
    0x8,
    0xC,
    0x3,
    0x7,
    0xB,
    0xF,
    0x6,
    0x2,
    0xE,
    0xA,
    0x5,
    0x1,
    0xD,
    0x9,
    0x0,
    0x5,
    0xA,
    0xF,
    0x7,
    0x2,
    0xD,
    0x8,
    0xE,
    0xB,
    0x4,
    0x1,
    0x9,
    0xC,
    0x3,
    0x6,
    0x0,
    0x6,
    0xC,
    0xA,
    0xB,
    0xD,
    0x7,
    0x1,
    0x5,
    0x3,
    0x9,
    0xF,
    0xE,
    0x8,
    0x2,
    0x4,
    0x0,
    0x7,
    0xE,
    0x9,
    0xF,
    0x8,
    0x1,
    0x6,
    0xD,
    0xA,
    0x3,
    0x4,
    0x2,
    0x5,
    0xC,
    0xB,
    0x0,
    0x8,
    0x3,
    0xB,
    0x6,
    0xE,
    0x5,
    0xD,
    0xC,
    0x4,
    0xF,
    0x7,
    0xA,
    0x2,
    0x9,
    0x1,
    0x0,
    0x9,
    0x1,
    0x8,
    0x2,
    0xB,
    0x3,
    0xA,
    0x4,
    0xD,
    0x5,
    0xC,
    0x6,
    0xF,
    0x7,
    0xE,
    0x0,
    0xA,
    0x7,
    0xD,
    0xE,
    0x4,
    0x9,
    0x3,
    0xF,
    0x5,
    0x8,
    0x2,
    0x1,
    0xB,
    0x6,
    0xC,
    0x0,
    0xB,
    0x5,
    0xE,
    0xA,
    0x1,
    0xF,
    0x4,
    0x7,
    0xC,
    0x2,
    0x9,
    0xD,
    0x6,
    0x8,
    0x3,
    0x0,
    0xC,
    0xB,
    0x7,
    0x5,
    0x9,
    0xE,
    0x2,
    0xA,
    0x6,
    0x1,
    0xD,
    0xF,
    0x3,
    0x4,
    0x8,
    0x0,
    0xD,
    0x9,
    0x4,
    0x1,
    0xC,
    0x8,
    0x5,
    0x2,
    0xF,
    0xB,
    0x6,
    0x3,
    0xE,
    0xA,
    0x7,
    0x0,
    0xE,
    0xF,
    0x1,
    0xD,
    0x3,
    0x2,
    0xC,
    0x9,
    0x7,
    0x6,
    0x8,
    0x4,
    0xA,
    0xB,
    0x5,
    0x0,
    0xF,
    0xD,
    0x2,
    0x9,
    0x6,
    0x4,
    0xB,
    0x1,
    0xE,
    0xC,
    0x3,
    0x8,
    0x7,
    0x5,
    0xA,
]

_AUT64_TABLE_SUB = [0, 1, 9, 0xE, 0xD, 0xB, 7, 6, 0xF, 2, 0xC, 5, 0xA, 4, 3, 8]

# Round key index tables (12 rounds x 8 positions)
_AUT64_TABLE_LN = [
    [4, 5, 6, 7, 0, 1, 2, 3],
    [5, 4, 7, 6, 1, 0, 3, 2],
    [6, 7, 4, 5, 2, 3, 0, 1],
    [7, 6, 5, 4, 3, 2, 1, 0],
    [0, 1, 2, 3, 4, 5, 6, 7],
    [1, 0, 3, 2, 5, 4, 7, 6],
    [2, 3, 0, 1, 6, 7, 4, 5],
    [3, 2, 1, 0, 7, 6, 5, 4],
    [5, 4, 7, 6, 1, 0, 3, 2],
    [4, 5, 6, 7, 0, 1, 2, 3],
    [7, 6, 5, 4, 3, 2, 1, 0],
    [6, 7, 4, 5, 2, 3, 0, 1],
]
_AUT64_TABLE_UN = [
    [1, 0, 3, 2, 5, 4, 7, 6],
    [0, 1, 2, 3, 4, 5, 6, 7],
    [3, 2, 1, 0, 7, 6, 5, 4],
    [2, 3, 0, 1, 6, 7, 4, 5],
    [5, 4, 7, 6, 1, 0, 3, 2],
    [4, 5, 6, 7, 0, 1, 2, 3],
    [7, 6, 5, 4, 3, 2, 1, 0],
    [6, 7, 4, 5, 2, 3, 0, 1],
    [3, 2, 1, 0, 7, 6, 5, 4],
    [2, 3, 0, 1, 6, 7, 4, 5],
    [1, 0, 3, 2, 5, 4, 7, 6],
    [0, 1, 2, 3, 4, 5, 6, 7],
]


def aut64_unpack(packed):
    """
    Unpack a 16-byte packed AUT64 key into (index, key[8], pbox[8], sbox[16]).

    Args:
        packed: list of 16 bytes
    Returns:
        dict with index, key, pbox, sbox
    """
    index = packed[0]
    key = [0] * 8
    for i in range(4):
        key[i * 2] = packed[i + 1] >> 4
        key[i * 2 + 1] = packed[i + 1] & 0xF
    pbox_val = (packed[5] << 16) | (packed[6] << 8) | packed[7]
    pbox = [0] * 8
    for i in range(7, -1, -1):
        pbox[i] = pbox_val & 0x7
        pbox_val >>= 3
    sbox = [0] * 16
    for i in range(8):
        sbox[i * 2] = packed[i + 8] >> 4
        sbox[i * 2 + 1] = packed[i + 8] & 0xF
    return {"index": index, "key": key, "pbox": pbox, "sbox": sbox}


def _aut64_key_nibble(key, nibble, table, iteration):
    kv = key[table[iteration]]
    return _AUT64_TABLE_OFFSET[(kv << 4) | nibble]


def _aut64_round_key(key_nib, state, round_n):
    rh, rl = 0, 0
    for i in range(7):
        rh ^= _aut64_key_nibble(key_nib, state[i] >> 4, _AUT64_TABLE_UN[round_n], i)
        rl ^= _aut64_key_nibble(key_nib, state[i] & 0xF, _AUT64_TABLE_LN[round_n], i)
    return (rh << 4) | rl


def aut64_decrypt(data_bytes, key_bytes, sbox, pbox):
    """
    AUT64 decrypt (Flipper-ARF algorithm).

    Full 12-round Feistel cipher with GF(2^4) round keys.

    Args:
        data_bytes: list of 8 bytes (64-bit block)
        key_bytes: list of 8 nibble values (key[0..7])
        sbox: list of 16 substitution values
        pbox: list of 8 permutation indices
    Returns:
        list of 8 decrypted bytes
    """
    msg = list(data_bytes)
    for rnd in range(AUT64_ROUNDS - 1, -1, -1):
        # Substitute byte 7
        msg[7] = (sbox[msg[7] >> 4] << 4) | sbox[msg[7] & 0xF]
        # Permute bits of byte 7
        pb = 0
        for i in range(8):
            if msg[7] & (1 << i):
                pb |= 1 << pbox[i]
        msg[7] = pb
        # Substitute again
        msg[7] = (sbox[msg[7] >> 4] << 4) | sbox[msg[7] & 0xF]
        # Decrypt compress
        rk = _aut64_round_key(key_bytes, msg, rnd)
        rk_hi, rk_lo = rk >> 4, rk & 0xF
        fb_hi = _AUT64_TABLE_SUB[key_bytes[_AUT64_TABLE_UN[rnd][7]]] << 4
        fb_lo = _AUT64_TABLE_SUB[key_bytes[_AUT64_TABLE_LN[rnd][7]]] << 4
        msg[7] = (
            _AUT64_TABLE_OFFSET[((rk_hi ^ (msg[7] >> 4)) & 0xF) + fb_hi] << 4
        ) | _AUT64_TABLE_OFFSET[((rk_lo ^ (msg[7] & 0xF)) & 0xF) + fb_lo]
        # Permute bytes
        tmp = [0] * 8
        for i in range(8):
            tmp[pbox[i]] = msg[i]
        msg = tmp
    return msg


def aut64_encrypt(data_bytes, key_bytes, sbox, pbox):
    """
    AUT64 encrypt (Flipper-ARF algorithm).

    Args:
        Same as aut64_decrypt.
    Returns:
        list of 8 encrypted bytes
    """
    # Build reverse key (inverse sbox, inverse pbox)
    inv_sbox = [0] * 16
    for i in range(16):
        inv_sbox[sbox[i]] = i
    inv_pbox = [0] * 8
    for i in range(8):
        inv_pbox[pbox[i]] = i

    msg = list(data_bytes)
    for rnd in range(AUT64_ROUNDS):
        # Reverse permute bytes
        tmp = [0] * 8
        for i in range(8):
            tmp[inv_pbox[i]] = msg[i]
        msg = tmp
        # Encrypt compress
        rk = _aut64_round_key(key_bytes, msg, rnd)
        rk_hi, rk_lo = rk >> 4, rk & 0xF
        fb_hi = _AUT64_TABLE_SUB[key_bytes[_AUT64_TABLE_UN[rnd][7]]] << 4
        fb_lo = _AUT64_TABLE_SUB[key_bytes[_AUT64_TABLE_LN[rnd][7]]] << 4
        # Find nibble that maps to msg[7] nibbles
        hi_nib, lo_nib = msg[7] >> 4, msg[7] & 0xF
        enc_hi, enc_lo = 0, 0
        for j in range(16):
            if _AUT64_TABLE_OFFSET[fb_hi + j] == hi_nib:
                enc_hi = j
                break
        for j in range(16):
            if _AUT64_TABLE_OFFSET[fb_lo + j] == lo_nib:
                enc_lo = j
                break
        msg[7] = ((enc_hi ^ rk_hi) << 4) | (enc_lo ^ rk_lo)
        # Substitute with inverse
        msg[7] = (inv_sbox[msg[7] >> 4] << 4) | inv_sbox[msg[7] & 0xF]
        # Permute bits with inverse
        pb = 0
        for i in range(8):
            if msg[7] & (1 << i):
                pb |= 1 << inv_pbox[i]
        msg[7] = pb
        # Substitute with inverse
        msg[7] = (inv_sbox[msg[7] >> 4] << 4) | inv_sbox[msg[7] & 0xF]
    return msg


# ═══════════════════════════════════════════════════════════
# KIA V5 Mixer Cipher
# Used by: KIA V5
# Encrypted: 32 bits -> Counter: 16 bits
# Key: 64 bits (8 bytes), Rounds: 18 x 8
# ═══════════════════════════════════════════════════════════

KIA_V5_KEYSTORE = [0x53, 0x54, 0x46, 0x52, 0x4B, 0x45, 0x30, 0x30]  # "STFRKE00"


def kia_v5_mixer_decrypt(encrypted, key_bytes=None):
    """
    KIA V5 mixer cipher decrypt (Flipper-ARF algorithm).

    18 rounds, 8 steps per round. Substitution constants: 0x74, 0x2E, 0x3A, 0x5C.

    Args:
        encrypted: 32-bit encrypted value
        key_bytes: list of 8 key bytes (default: KIA_V5_KEYSTORE "STFRKE00")
    Returns:
        16-bit decrypted counter value
    """
    if key_bytes is None:
        key_bytes = KIA_V5_KEYSTORE

    s0 = encrypted & 0xFF
    s1 = (encrypted >> 8) & 0xFF
    s2 = (encrypted >> 16) & 0xFF
    s3 = (encrypted >> 24) & 0xFF

    round_idx = 1
    for _ in range(18):
        r = key_bytes[round_idx]
        for _ in range(8):
            # Substitution based on s3 bits
            if s3 & 0x40 == 0:
                base = 0x74 if s3 & 0x02 == 0 else 0x2E
            else:
                base = 0x3A if s3 & 0x02 == 0 else 0x5C
            if s2 & 0x08:
                base = ((base & 0x0F) << 4) | ((base >> 4) & 0x0F)
            if s1 & 0x01:
                base = ((base & 0x3F) << 2) & 0xFF
            if s0 & 0x01:
                base = (base << 1) & 0xFF

            # Shift register left by 1
            temp = s3 ^ s1
            s3 = ((s3 << 1) | (s2 >> 7)) & 0xFF
            s2 = ((s2 << 1) | (s1 >> 7)) & 0xFF
            s1 = ((s1 << 1) | (s0 >> 7)) & 0xFF
            s0 = (s0 << 1) & 0xFF

            # Feedback
            chk = base ^ r ^ temp
            if chk & 0x80:
                s0 |= 0x01
            r = (r << 1) & 0xFF

        round_idx = (round_idx - 1) & 0x7

    return (s0 + (s1 << 8)) & 0xFFFF


# ═══════════════════════════════════════════════════════════
# Mitsubishi V0 XOR Scrambling
# Used by: Mitsubishi V0
# Input: byte array + 16-bit counter
# ═══════════════════════════════════════════════════════════


def mitsubishi_v0_scramble(payload, counter):
    """
    Mitsubishi V0 XOR scramble.

    Args:
        payload: list of bytes (at least 8)
        counter: 16-bit counter

    Returns:
        list of scrambled bytes
    """
    result = list(payload)
    hi = (counter >> 8) & 0xFF
    lo = counter & 0xFF

    mask1 = (hi & 0xAA) | (lo & 0x55)
    mask2 = (lo & 0xAA) | (hi & 0x55)
    mask3 = mask1 ^ mask2

    # XOR serial bytes 0-3 with mask3 (NOT byte 4 — counter stays clear)
    for i in range(min(4, len(result))):
        result[i] ^= mask3

    # Invert first 8 bytes
    for i in range(min(8, len(result))):
        result[i] = (~result[i]) & 0xFF

    return result


def mitsubishi_v0_descramble(payload, counter):
    """
    Mitsubishi V0 XOR descramble (reverse of scramble).
    Since invert is its own inverse and XOR is its own inverse,
    just apply the same operations in reverse order.
    """
    result = list(payload)

    # Un-invert first 8 bytes
    for i in range(min(8, len(result))):
        result[i] = (~result[i]) & 0xFF

    # Un-XOR serial bytes 0-3
    hi = (counter >> 8) & 0xFF
    lo = counter & 0xFF
    mask1 = (hi & 0xAA) | (lo & 0x55)
    mask2 = (lo & 0xAA) | (hi & 0x55)
    mask3 = mask1 ^ mask2
    for i in range(min(4, len(result))):
        result[i] ^= mask3

    return result


def mitsubishi_v0_decode(raw_payload):
    """
    Full Mitsubishi V0 decode from raw 96-bit (12-byte) captured frame.

    The counter is embedded in the frame (bytes 4-5). The XOR mask
    is derived from the counter and applied to serial bytes 0-3 only.
    No external key needed — pure obfuscation, no cryptographic security.

    Decode order (reverse of encode: XOR→invert):
    1. Invert bytes 0-7 (undo inversion)
    2. Read counter from bytes 4-5 (now clear — not XOR'd)
    3. XOR bytes 0-3 with counter-derived mask3 (undo XOR)

    Args:
        raw_payload: list of 12 raw bytes from the captured frame

    Returns:
        dict with serial, counter, button, id_byte, raw_descrambled
    """
    if len(raw_payload) < 10:
        return {"error": f"Need 12 bytes, got {len(raw_payload)}"}

    buf = list(raw_payload[:12])
    while len(buf) < 12:
        buf.append(0)

    # Stage 1: byte inversion (bytes 0-7)
    for i in range(8):
        buf[i] = (~buf[i]) & 0xFF

    # Counter is now in clear at bytes 4-5 (only inverted, not XOR'd)
    counter = (buf[4] << 8) | buf[5]

    # Stage 2: counter-derived XOR on serial bytes 0-3 only
    hi = (counter >> 8) & 0xFF
    lo = counter & 0xFF
    mask1 = (hi & 0xAA) | (lo & 0x55)
    mask2 = (lo & 0xAA) | (hi & 0x55)
    mask3 = mask1 ^ mask2
    for i in range(4):
        buf[i] ^= mask3

    serial = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3]
    button = buf[6]
    id_byte = buf[9]

    return {
        "serial": serial,
        "counter": counter,
        "button": button,
        "id_byte": id_byte,
        "raw_descrambled": buf,
    }


# ═══════════════════════════════════════════════════════════
# Ford V0 GF(2) Matrix CRC
# Used by: Ford V0 car keys
# Matrix: 8x8 bytes, Output: 8-bit CRC
# ═══════════════════════════════════════════════════════════

FORD_V0_CRC_MATRIX = [
    0xDA,
    0xB5,
    0x55,
    0x6A,
    0xAA,
    0xAA,
    0xAA,
    0xD5,
    0xB6,
    0x6C,
    0xCC,
    0xD9,
    0x99,
    0x99,
    0x99,
    0xB3,
    0x71,
    0xE3,
    0xC3,
    0xC7,
    0x87,
    0x87,
    0x87,
    0x8F,
    0x0F,
    0xE0,
    0x3F,
    0xC0,
    0x7F,
    0x80,
    0x7F,
    0x80,
    0x00,
    0x1F,
    0xFF,
    0xC0,
    0x00,
    0x7F,
    0xFF,
    0x80,
    0x00,
    0x00,
    0x00,
    0x3F,
    0xFF,
    0xFF,
    0xFF,
    0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x7F,
    0x23,
    0x12,
    0x94,
    0x84,
    0x35,
    0xF4,
    0x55,
    0x84,
]


def _popcount8(x):
    count = 0
    while x:
        count += x & 1
        x >>= 1
    return count


def ford_v0_calculate_crc(buf):
    """
    Ford V0 GF(2) matrix CRC.

    Args:
        buf: list of at least 9 bytes (bytes 1-8 used)

    Returns:
        8-bit CRC value
    """
    crc = 0
    for row in range(8):
        xor_sum = 0
        for col in range(8):
            xor_sum ^= FORD_V0_CRC_MATRIX[row * 8 + col] & buf[col + 1]
        if _popcount8(xor_sum) & 1:
            crc |= 1 << row
    return crc


def ford_v0_calculate_bs(counter, button, bs_magic=0x6F):
    """
    Ford V0 BS (checksum byte) calculation.

    Args:
        counter: counter value (low byte used)
        button: 4-bit button code
        bs_magic: magic constant (default 0x6F)

    Returns:
        8-bit BS value
    """
    return ((counter & 0xFF) + bs_magic + (button << 4)) & 0xFF


# ── Ford V0 full protocol decoder/encoder ──────────────────
# Based on Flipper-ARF ford_v0.c (D4C1-Labs)
#
# The Ford V0 keyfob transmits 80 Manchester-encoded bits:
#   key1 (64 bits) + key2 (16 bits)
# Both are transmitted INVERTED (~key1, ~key2) over the air.
#
# URH's Thomas-convention Manchester (10→0, 01→1) produces
# bits that are the complement of Flipper's IEEE convention,
# which cancels with Flipper's inversion step. So URH's
# decoded 80 bits directly correspond to key1 | key2.
#
# The payload is XOR-obfuscated + bit-interleaved.
# After de-obfuscation, the fields are:
#   buf[0]    : fixed/type byte
#   buf[1..4] : serial number (32 bits, little-endian → big-endian)
#   buf[5]    : button(4 high) | counter[19:16](4 low)
#   buf[6]    : counter[15:8]
#   buf[7]    : counter[7:0]
#   key2>>8   : checksum (sum of buf[1..7])
#   key2&0xFF : CRC


FORD_V0_BUTTON_NAMES = {
    0x01: "Lock",
    0x02: "Unlock",
    0x04: "Trunk",
}


def ford_v0_decode(key1, key2):
    """
    Ford V0 full protocol decode (Flipper-ARF algorithm).

    Takes the Manchester-decoded key1 (64-bit int) and key2 (16-bit int)
    as produced by URH's Manchester decoder, and extracts the
    de-obfuscated fields: serial, button, counter.

    Args:
        key1: 64-bit integer (first 64 decoded bits)
        key2: 16-bit integer (last 16 decoded bits)

    Returns:
        dict with keys: serial, button, button_name, counter,
                        checksum_ok, crc_ok, buf (raw de-obfuscated bytes)
    """
    # Serialize key1 into buf[0..7] big-endian
    buf = [0] * 12
    for i in range(8):
        buf[7 - i] = (key1 >> (i * 8)) & 0xFF

    # Serialize key2 into buf[8..9]
    buf[8] = (key2 >> 8) & 0xFF  # checksum byte
    buf[9] = key2 & 0xFF  # CRC byte

    # Compute parity of checksum byte
    parity = _parity8(buf[8])
    buf[11] = parity

    # XOR de-obfuscation
    if parity:
        xor_byte = buf[7]
        for i in range(1, 7):
            buf[i] ^= xor_byte
    else:
        xor_byte = buf[6]
        for i in range(1, 6):
            buf[i] ^= xor_byte
        buf[7] ^= xor_byte

    # Bit interleave buf[6] and buf[7]
    old6, old7 = buf[6], buf[7]
    buf[7] = (old7 & 0xAA) | (old6 & 0x55)
    buf[6] = (old6 & 0xAA) | (old7 & 0x55)

    # Extract serial (buf[1..4], stored big-endian, read as LE then swap)
    serial_le = buf[1] | (buf[2] << 8) | (buf[3] << 16) | (buf[4] << 24)
    # Byte-swap to big-endian
    serial = (
        ((serial_le >> 24) & 0xFF)
        | (((serial_le >> 16) & 0xFF) << 8)
        | (((serial_le >> 8) & 0xFF) << 16)
        | ((serial_le & 0xFF) << 24)
    )

    # Button: upper nibble of buf[5]
    button = (buf[5] >> 4) & 0x0F

    # Counter: 20 bits from buf[5] low nibble + buf[6] + buf[7]
    counter = ((buf[5] & 0x0F) << 16) | (buf[6] << 8) | buf[7]

    # Verify checksum: sum of buf[1..7]
    checksum_calc = sum(buf[1:8]) & 0xFF
    checksum_ok = checksum_calc == buf[8]

    # Verify CRC using GF(2) matrix on ORIGINAL (obfuscated) key bytes.
    # The CRC is computed before de-obfuscation, using key1 bytes + checksum.
    crc_buf = [0] * 10
    for i in range(8):
        crc_buf[7 - i] = (key1 >> (i * 8)) & 0xFF
    crc_buf[8] = (key2 >> 8) & 0xFF  # checksum
    crc_calc = ford_v0_calculate_crc(crc_buf)
    # CRC bit 7 is inverted in transmission
    crc_ok = crc_calc == ((key2 & 0xFF) ^ 0x80)

    button_name = FORD_V0_BUTTON_NAMES.get(button, f"0x{button:02X}")

    return {
        "serial": serial,
        "button": button,
        "button_name": button_name,
        "counter": counter,
        "checksum_ok": checksum_ok,
        "crc_ok": crc_ok,
        "buf": list(buf[:10]),
        "key1_hex": f"{key1:016X}",
        "key2_hex": f"{key2:04X}",
    }


def ford_v0_encode(serial, button, counter, fixed_byte=0x55):
    """
    Ford V0 full protocol encode (Flipper-ARF algorithm).

    Takes serial, button, counter and produces key1 + key2
    ready for Manchester encoding.

    Args:
        serial: 32-bit serial number
        button: 4-bit button code (1=Lock, 2=Unlock, 4=Trunk)
        counter: 20-bit counter value
        fixed_byte: buf[0] byte (default 0x55, preserved from decode)

    Returns:
        (key1, key2) as (64-bit int, 16-bit int)
    """
    buf = [0] * 12
    buf[0] = fixed_byte & 0xFF

    # Place serial (big-endian → LE bytes in buf[1..4])
    serial_be = serial & 0xFFFFFFFF
    serial_le = (
        ((serial_be >> 24) & 0xFF)
        | (((serial_be >> 16) & 0xFF) << 8)
        | (((serial_be >> 8) & 0xFF) << 16)
        | ((serial_be & 0xFF) << 24)
    )
    buf[1] = serial_le & 0xFF
    buf[2] = (serial_le >> 8) & 0xFF
    buf[3] = (serial_le >> 16) & 0xFF
    buf[4] = (serial_le >> 24) & 0xFF

    # Button + counter high nibble in buf[5]
    buf[5] = ((button & 0x0F) << 4) | ((counter >> 16) & 0x0F)
    buf[6] = (counter >> 8) & 0xFF
    buf[7] = counter & 0xFF

    # Compute checksum = sum of buf[1..7]
    checksum = sum(buf[1:8]) & 0xFF
    buf[8] = checksum

    # Bit interleave buf[6] and buf[7] (same swap, it's its own inverse)
    old6, old7 = buf[6], buf[7]
    buf[7] = (old7 & 0xAA) | (old6 & 0x55)
    buf[6] = (old6 & 0xAA) | (old7 & 0x55)

    # Compute parity of checksum for XOR obfuscation
    parity = _parity8(checksum)

    # XOR obfuscation (inverse of de-obfuscation)
    if parity:
        xor_byte = buf[7]
        for i in range(1, 7):
            buf[i] ^= xor_byte
    else:
        xor_byte = buf[6]
        for i in range(1, 6):
            buf[i] ^= xor_byte
        buf[7] ^= xor_byte

    # Compute CRC and invert bit 7
    crc = ford_v0_calculate_crc(buf)
    buf[9] = crc ^ 0x80

    # Reconstruct key1 from buf[0..7]
    key1 = 0
    for i in range(8):
        key1 |= buf[7 - i] << (i * 8)

    # key2 = checksum << 8 | crc_byte
    key2 = (buf[8] << 8) | buf[9]

    return key1, key2


def ford_v0_decode_bits(decoded_bits):
    """
    Convenience: decode Ford V0 from a string of 80 Manchester-decoded bits.

    Args:
        decoded_bits: string of '0'/'1', 80 bits from URH Manchester decode

    Returns:
        dict with serial, button, counter, crc_ok, etc.
    """
    if len(decoded_bits) < 80:
        return {"error": f"Need 80 bits, got {len(decoded_bits)}"}

    key1 = int(decoded_bits[:64], 2)
    key2 = int(decoded_bits[64:80], 2)
    return ford_v0_decode(key1, key2)


def _parity8(x):
    """Compute parity (XOR of all bits) of an 8-bit value."""
    x ^= x >> 4
    x ^= x >> 2
    x ^= x >> 1
    return x & 1


# ═══════════════════════════════════════════════════════════
# PSA Second-Stage XOR Permutation
# Used by: PSA Peugeot/Citroen
# Input: 6-byte buffer
# ═══════════════════════════════════════════════════════════


def psa_xor_encrypt(buf):
    """
    PSA second-stage XOR permutation encrypt.

    Args:
        buf: list of at least 7 bytes (indices 0-6)

    Returns:
        list of encrypted bytes
    """
    result = list(buf)
    e = list(buf)
    e[6] = result[5] ^ e[6] ^ e[5]  # placeholder
    e[0] = result[2] ^ e[5]
    e[2] = result[4] ^ e[0]
    e[4] = result[3] ^ e[2]
    e[3] = result[0] ^ e[5]
    e[1] = result[1] ^ e[3]
    return e


def psa_xor_decrypt(buf):
    """
    PSA second-stage XOR permutation decrypt.

    Args:
        buf: list of at least 7 encrypted bytes

    Returns:
        list of decrypted bytes
    """
    e = list(buf)
    result = [0] * len(buf)
    result[1] = e[1] ^ e[3]
    result[0] = e[3] ^ e[5]
    result[3] = e[4] ^ e[2]
    result[4] = e[2] ^ e[0]
    result[2] = e[0] ^ e[5]
    result[5] = e[6] ^ e[5] ^ e[6]
    for i in range(7, len(buf)):
        result[i] = buf[i]
    return result


# ═══════════════════════════════════════════════════════════
# CRC utilities
# ═══════════════════════════════════════════════════════════


def crc8(data, poly=0x07, init=0x00):
    """
    Generic CRC-8.

    Args:
        data: list of bytes
        poly: polynomial (default 0x07)
        init: initial value

    Returns:
        8-bit CRC
    """
    crc = init
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = ((crc << 1) ^ poly) & 0xFF
            else:
                crc = (crc << 1) & 0xFF
    return crc


def crc16_ccitt(data, poly=0x8005, init=0x0000):
    """
    CRC-16 CCITT.

    Args:
        data: list of bytes
        poly: polynomial (default 0x8005)
        init: initial value

    Returns:
        16-bit CRC
    """
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


# ═══════════════════════════════════════════════════════════
# Nice Flor-S — Rainbow table + XOR deobfuscation
# Used by: NICE Flor-S gate remotes (52/72-bit)
# ═══════════════════════════════════════════════════════════


def nice_flor_s_decrypt(data_52bit, rainbow_table):
    """
    Nice Flor-S decrypt using rainbow table (Flipper-ARF algorithm).

    Two rounds of table-lookup XOR with byte permutation.

    Args:
        data_52bit: 52-bit encrypted value (int, LE layout)
        rainbow_table: 32-byte lookup table (list of ints)
    Returns:
        dict with serial, counter, button
    """
    p = list(data_52bit.to_bytes(8, "little"))

    # Initial byte permutation with NOT
    k = (~p[4]) & 0xFF
    p[5] = (~p[5]) & 0xFF
    p[4] = (~p[2]) & 0xFF
    p[2] = (~p[0]) & 0xFF
    p[0] = k
    k = (~p[3]) & 0xFF
    p[3] = (~p[1]) & 0xFF
    p[1] = k

    # Two rounds of table-lookup XOR
    for y in range(2):
        k = (rainbow_table[p[0] >> 3] + 0x25) & 0xFF
        for i in range(1, 6):
            p[i] ^= k
        p[5] &= 0x0F
        p[0] ^= k & 0x7

        k = rainbow_table[p[0] & 0x1F]
        for i in range(1, 6):
            p[i] ^= k
        p[5] &= 0x0F
        p[0] ^= k & 0xE0

        if y == 0:
            p[0], p[1] = p[1], p[0]

    dec = int.from_bytes(p[:8], "little")
    return {
        "counter": dec & 0xFFFF,
        "serial": (dec >> 16) & 0xFFFFFFF,
        "button": (dec >> 48) & 0xF,
    }


# ═══════════════════════════════════════════════════════════
# Somfy Telis / Keytis — Rolling XOR shift
# Used by: Somfy RTS blinds/shutters (56/80-bit)
# ═══════════════════════════════════════════════════════════


def somfy_decode(data_56bit):
    """
    Somfy Telis XOR deobfuscation (Flipper-ARF algorithm).

    Cascading XOR: data ^= (data >> 8).

    Args:
        data_56bit: 56-bit raw captured frame (int, MSB-first)
    Returns:
        dict with button, counter, address, crc_ok
    """
    # Cascading XOR deobfuscation
    clear = data_56bit ^ (data_56bit >> 8)

    # CRC: XOR all nibbles, result should be 0
    crc = 0
    tmp = clear
    for _ in range(14):  # 56 bits = 14 nibbles
        crc ^= tmp & 0xF
        tmp >>= 4

    button = (clear >> 44) & 0xF
    counter = (clear >> 24) & 0xFFFF
    address = clear & 0xFFFFFF

    return {
        "button": button,
        "counter": counter,
        "address": address,
        "crc_ok": crc == 0,
    }


def somfy_encode(button, counter, address):
    """Somfy Telis XOR obfuscation (encode for TX)."""
    # Build clear frame: key_byte(8) | btn(4) | crc(4) | counter(16) | addr(24)
    frame = 0xA0 << 48  # key byte MSN = 0xA
    frame |= (button & 0xF) << 44
    frame |= (counter & 0xFFFF) << 24
    frame |= address & 0xFFFFFF
    # Compute CRC = XOR of all nibbles (with CRC nibble = 0)
    crc = 0
    tmp = frame
    for _ in range(14):
        crc ^= tmp & 0xF
        tmp >>= 4
    frame |= (crc & 0xF) << 40
    # Apply XOR obfuscation (cascade)
    obf = frame
    for i in range(6, 0, -1):
        byte_above = (obf >> ((i) * 8)) & 0xFF
        obf ^= byte_above << ((i - 1) * 8)
    return obf


# ═══════════════════════════════════════════════════════════
# Came Atomo — XOR cipher with bit shifting
# Used by: Came Atomo gate remotes (62-bit)
# ═══════════════════════════════════════════════════════════


def came_atomo_decrypt(data_62bit):
    """
    Came Atomo LFSR-based cipher decrypt (Flipper-ARF algorithm).

    Args:
        data_62bit: 62-bit captured payload (int)
    Returns:
        dict with serial, counter, counter2, button
    """
    # Invert all bits and shift left 4
    data = (data_62bit ^ 0x3FFFFFFFFFFFFFFF) << 4
    buf = [(data >> (56 - i * 8)) & 0xFF for i in range(8)]

    # LFSR cipher
    buf[0] = (buf[0] ^ 5) & 0x7F
    tmp = (-buf[0]) & 0x7F
    bit_cnt = 8
    while bit_cnt < 59:
        if (tmp & 0x18) and (((tmp // 8) & 3) != 3):
            tmp = ((tmp << 1) & 0xFF) | 1
        else:
            tmp = (tmp << 1) & 0xFF
        if tmp & 0x80:
            buf[bit_cnt // 8] ^= 0x80 >> (bit_cnt & 7)
        bit_cnt += 1

    cnt2 = buf[0] & 0x7F
    counter = (buf[1] << 8) | buf[2]
    serial = (buf[3] << 24) | (buf[4] << 16) | (buf[5] << 8) | buf[6]
    btn_raw = buf[7] >> 4
    btn_map = {0x0: 1, 0x2: 2, 0x4: 3, 0x6: 4}

    return {
        "serial": serial,
        "counter": counter,
        "counter2": cnt2,
        "button": btn_map.get(btn_raw, 0),
    }


# ═══════════════════════════════════════════════════════════
# Came Twee — XOR with 15-entry rainbow table
# Used by: Came Twee gate remotes (54-bit)
# ═══════════════════════════════════════════════════════════

CAME_TWEE_XOR_TABLE = [
    0x0E0E0E00,
    0x1D1D1D11,
    0x2C2C2C22,
    0x3B3B3B33,
    0x4A4A4A44,
    0x59595955,
    0x68686866,
    0x77777777,
    0x86868688,
    0x95959599,
    0xA4A4A4AA,
    0xB3B3B3BB,
    0xC2C2C2CC,
    0xD1D1D1DD,
    0xE0E0E0EE,
]


def came_twee_decrypt(data_54bit):
    """
    Came Twee XOR deobfuscation (Flipper-ARF algorithm).

    Args:
        data_54bit: 54-bit captured frame (int)
    Returns:
        dict with serial, button, dip_switch
    """
    parcel_idx = data_54bit & 0xF
    if parcel_idx >= 15:
        parcel_idx = 0
    data_lo = data_54bit & 0xFFFFFFFF
    data_lo ^= CAME_TWEE_XOR_TABLE[parcel_idx]
    serial = data_lo
    button = (data_lo >> 4) & 0x0F
    # DIP switch: bits 16-25, reversed
    dip_raw = (data_lo >> 16) & 0x3FF
    dip = 0
    for i in range(10):
        if dip_raw & (1 << i):
            dip |= 1 << (9 - i)
    return {
        "serial": serial,
        "button": button,
        "dip_switch": dip >> 6,
        "parcel": parcel_idx,
    }


# ═══════════════════════════════════════════════════════════
# Scher-Khan — Pi-derived XOR table + bit shuffle
# Used by: Scher-Khan Magicar car alarms (35-82 bit)
# ═══════════════════════════════════════════════════════════

# First 146 bytes of Pi fractional part (hex)
SCHER_KHAN_PI_TABLE = [
    0x24,
    0x3F,
    0x6A,
    0x88,
    0x85,
    0xA3,
    0x08,
    0xD3,
    0x13,
    0x19,
    0x8A,
    0x2E,
    0x03,
    0x70,
    0x73,
    0x44,
    0xA4,
    0x09,
    0x38,
    0x22,
    0x29,
    0x9F,
    0x31,
    0xD0,
    0x08,
    0x2E,
    0xFA,
    0x98,
    0xEC,
    0x4E,
    0x6C,
    0x89,
    0x45,
    0x28,
    0x21,
    0xE6,
    0x38,
    0xD0,
    0x13,
    0x77,
    0xBE,
    0x54,
    0x66,
    0xCF,
    0x34,
    0xE9,
    0x0C,
    0x6C,
    0xC0,
    0xAC,
    0x29,
    0xB7,
    0xC9,
    0x7C,
    0x50,
    0xDD,
    0x3F,
    0x84,
    0xD5,
    0xB5,
    0xB5,
    0x47,
    0x09,
    0x17,
    0x92,
    0x16,
    0xD5,
    0xD9,
    0x89,
    0x79,
    0xFB,
    0x1B,
    0xD1,
    0x31,
    0x0B,
    0xA6,
    0x98,
    0xDF,
    0xB5,
    0xAC,
    0x2F,
    0xFD,
    0x72,
    0xDB,
    0xD0,
    0x1A,
    0xDF,
    0xB7,
    0xB8,
    0xE1,
    0xAF,
    0xED,
    0x6A,
    0x26,
    0x7E,
    0x96,
    0xBA,
    0x7C,
    0x90,
    0x45,
    0xF1,
    0x2C,
    0x7F,
    0x99,
    0x24,
    0xA1,
    0x99,
    0x47,
    0xB3,
    0x91,
    0x6C,
    0xF7,
    0x08,
    0x01,
    0xF2,
    0xE2,
    0x85,
    0x8E,
    0xFC,
    0x16,
    0x63,
    0x69,
    0x20,
    0xD8,
    0x71,
    0x57,
    0x4E,
    0x69,
    0xA4,
    0x58,
    0xFE,
    0xA3,
    0xF4,
    0x93,
    0x3D,
    0x7E,
    0x0D,
    0x95,
    0x74,
    0x8F,
    0xCA,
    0xFB,
]


def scher_khan_decrypt(data_bytes, serial):
    """
    Scher-Khan XOR deobfuscation using Pi-derived table.

    Args:
        data_bytes: encrypted payload bytes (list of ints)
        serial: device serial number
    Returns:
        list of decrypted bytes
    """
    k = serial & 0xFF
    out = list(data_bytes)
    for i in range(len(out)):
        idx = (k + i) % len(SCHER_KHAN_PI_TABLE)
        out[i] ^= SCHER_KHAN_PI_TABLE[idx]
    return out


# ═══════════════════════════════════════════════════════════
# Phoenix V2 — 16-iteration XOR bit-shuffle
# Used by: Phoenix V2 gate remotes (52-bit)
# ═══════════════════════════════════════════════════════════


def phoenix_v2_decrypt(data_52bit):
    """
    Phoenix V2 bit-shuffle cipher (Flipper-ARF algorithm).

    16-iteration cipher keyed by serial bytes with MSB/LSB swap.

    Args:
        data_52bit: 52-bit captured value (int, already bit-reversed)
    Returns:
        dict with serial, counter, button
    """
    # Bit-reverse the full 52-bit key
    rev = 0
    tmp = data_52bit
    for _ in range(52):
        rev = (rev << 1) | (tmp & 1)
        tmp >>= 1

    serial = rev & 0xFFFFFFFF
    button = (rev >> 32) & 0xF
    encrypted = (rev >> 40) & 0xFFFF

    byte1 = (encrypted >> 8) & 0xFF
    byte2 = encrypted & 0xFF
    xor1 = (serial >> 8) & 0xFF  # serial byte 2 (LE)
    xor2 = serial & 0xFF  # serial byte 3 (LE)

    for _ in range(16):
        msb1 = byte1 & 0x80
        lsb2 = byte2 & 1
        byte2 = ((byte2 >> 1) | msb1) & 0xFF
        byte1 = ((byte1 << 1) | lsb2) & 0xFF
        if msb1 == 0:
            byte1 ^= xor1
            byte2 = (byte2 ^ xor2) & 0x7F

    counter = (byte2 << 8) | byte1
    return {"serial": serial, "counter": counter, "button": button}


# ═══════════════════════════════════════════════════════════
# Porsche Cayenne — 24-bit rotating register cipher
# Used by: Porsche Cayenne key fobs (64-bit)
# ═══════════════════════════════════════════════════════════


def porsche_cayenne_decrypt(pkt_64bit):
    """
    Porsche Cayenne 24-bit rotating register cipher (Flipper-ARF).

    Brute-forces cnt_lo (0-255) by trial-encrypting and comparing
    against pkt[4..7]. The cipher uses a 24-bit left-circular register
    seeded from serial bytes, rotated 4+cnt_lo times, then XOR'd with
    masked counter bytes to produce the authentication output.

    Args:
        pkt_64bit: 64-bit captured packet (int)
    Returns:
        dict with serial, button, counter, frame_type
    """
    pkt = [(pkt_64bit >> (56 - i * 8)) & 0xFF for i in range(8)]
    button = (pkt[0] >> 4) & 0xF
    frame_type = pkt[0] & 0x07
    serial = (pkt[1] << 16) | (pkt[2] << 8) | pkt[3]

    def _rotate24(rh, rm, rl):
        ch = (rh >> 7) & 1
        cm = (rm >> 7) & 1
        cl = (rl >> 7) & 1
        return ((rh << 1) | cm) & 0xFF, ((rm << 1) | cl) & 0xFF, ((rl << 1) | ch) & 0xFF

    def _encrypt(serial24, btn_byte, cnt_lo, cnt_hi):
        b0 = btn_byte
        r_h, r_m, r_l = serial24 & 0xFF, (serial24 >> 16) & 0xFF, (serial24 >> 8) & 0xFF
        for _ in range(4 + cnt_lo):
            r_h, r_m, r_l = _rotate24(r_h, r_m, r_l)
        a9A = r_h ^ b0
        p1 = ((~cnt_lo << 2) & 0xFC) ^ r_m
        p1 &= 0xCC
        p2 = ((~cnt_hi << 2) & 0xFC) ^ r_m
        p2 &= 0x30
        p3 = ((~cnt_hi >> 6) & 0x03) ^ r_m
        p3 &= 0x03
        a9B = (p1 | p2 | p3) & 0xFF
        q1 = ((~cnt_lo >> 2) & 0x3F) ^ r_l
        q1 &= 0x33
        q2 = (((~cnt_hi) & 0x03) << 6) ^ r_l
        q2 &= 0xC0
        q3 = ((~cnt_hi >> 2) & 0x3F) ^ r_l
        q3 &= 0x0C
        a9C = (q1 | q2 | q3) & 0xFF
        o4 = ((a9A >> 2) & 0x3F) | (((~cnt_lo) & 0x03) << 6)
        o5 = (
            ((~cnt_lo) & 0xC0)
            | ((a9A & 0x03) << 4)
            | (a9B & 0x0C)
            | (((~cnt_lo) >> 2) & 0x03)
        )
        o6 = ((a9B & 0x03) << 6) | ((a9C >> 2) & 0x3C) | (((~cnt_lo) >> 4) & 0x03)
        o7 = ((a9B >> 4) & 0x0F) | ((a9C & 0x0F) << 4)
        return o4 & 0xFF, o5 & 0xFF, o6 & 0xFF, o7 & 0xFF

    # Brute-force cnt_lo (0-255), try cnt_hi 0-255
    for cnt_lo in range(256):
        for cnt_hi in range(256):
            o4, o5, o6, o7 = _encrypt(serial, pkt[0], cnt_lo, cnt_hi)
            if o4 == pkt[4] and o5 == pkt[5] and o6 == pkt[6] and o7 == pkt[7]:
                counter = (cnt_hi << 8) | cnt_lo
                # The cipher internally does counter+1 before using it
                return {
                    "serial": serial,
                    "button": button,
                    "counter": max(0, counter - 1),
                    "frame_type": frame_type,
                }

    return {"serial": serial, "button": button, "counter": -1, "frame_type": frame_type}


# ═══════════════════════════════════════════════════════════
# Subaru — Rotating register XOR
# Used by: Subaru key fobs (64-bit)
# ═══════════════════════════════════════════════════════════


def subaru_decrypt(kb_8bytes):
    """
    Subaru counter decode (Flipper-ARF algorithm).

    Uses 24-bit serial rotation (4+lo steps) + scattered inverted
    bit extraction to recover the 16-bit rolling counter from the
    8-byte captured packet.

    Args:
        kb_8bytes: list of 8 captured bytes (KB[0..7])
    Returns:
        dict with serial, button, counter
    """
    KB = list(kb_8bytes[:8])

    # Button: low nibble of KB[0]
    button = KB[0] & 0x0F
    # Serial: KB[1..3]
    serial = (KB[1] << 16) | (KB[2] << 8) | KB[3]

    # Extract lo byte from scattered inverted bits
    lo = 0
    if (KB[4] & 0x40) == 0:
        lo |= 0x01
    if (KB[4] & 0x80) == 0:
        lo |= 0x02
    if (KB[5] & 0x01) == 0:
        lo |= 0x04
    if (KB[5] & 0x02) == 0:
        lo |= 0x08
    if (KB[6] & 0x01) == 0:
        lo |= 0x10
    if (KB[6] & 0x02) == 0:
        lo |= 0x20
    if (KB[5] & 0x40) == 0:
        lo |= 0x40
    if (KB[5] & 0x80) == 0:
        lo |= 0x80

    # Build register values REG_SH1 and REG_SH2
    REG_SH1 = (KB[7] << 4) & 0xF0
    if KB[5] & 0x04:
        REG_SH1 |= 0x04
    if KB[5] & 0x08:
        REG_SH1 |= 0x08
    if KB[6] & 0x80:
        REG_SH1 |= 0x02
    if KB[6] & 0x40:
        REG_SH1 |= 0x01

    REG_SH2 = ((KB[6] << 2) & 0xF0) | ((KB[7] >> 4) & 0x0F)

    # 24-bit left circular rotation of serial bytes by (4+lo) steps
    SER0, SER1, SER2 = KB[3], KB[1], KB[2]
    for _ in range(4 + lo):
        t_bit = (SER0 >> 7) & 1
        SER0 = ((SER0 << 1) & 0xFE) | ((SER1 >> 7) & 1)
        SER1 = ((SER1 << 1) & 0xFE) | ((SER2 >> 7) & 1)
        SER2 = ((SER2 << 1) & 0xFE) | t_bit

    # XOR rotated serial with register
    T1 = SER1 ^ REG_SH1
    T2 = SER2 ^ REG_SH2

    # Extract hi byte from scattered inverted bits of T1/T2
    hi = 0
    if (T1 & 0x10) == 0:
        hi |= 0x04
    if (T1 & 0x20) == 0:
        hi |= 0x08
    if (T2 & 0x80) == 0:
        hi |= 0x02
    if (T2 & 0x40) == 0:
        hi |= 0x01
    if (T1 & 0x01) == 0:
        hi |= 0x40
    if (T1 & 0x02) == 0:
        hi |= 0x80
    if (T2 & 0x08) == 0:
        hi |= 0x20
    if (T2 & 0x04) == 0:
        hi |= 0x10

    counter = (hi << 8) | lo

    return {
        "serial": serial,
        "button": button,
        "counter": counter,
    }


# ═══════════════════════════════════════════════════════════
# Mazda Siemens — Parity-selected XOR mask + byte inversion
# Used by: Mazda key fobs (64-bit)
# ═══════════════════════════════════════════════════════════


def mazda_siemens_decrypt(data_64bit):
    """
    Mazda Siemens parity-XOR deobfuscation (Flipper-ARF algorithm).

    Same pattern as Ford V0: parity selects XOR byte, then
    bit deinterleave on counter bytes.

    Args:
        data_64bit: 64-bit captured frame (int, 8 bytes)
    Returns:
        dict with serial, counter, button, checksum_ok
    """
    d = [(data_64bit >> (56 - i * 8)) & 0xFF for i in range(8)]

    # Parity of byte 7
    p = d[7]
    p ^= p >> 4
    p ^= p >> 2
    p ^= p >> 1
    parity = p & 1

    # XOR deobfuscation
    if parity:  # odd parity
        mask = d[6]
        for i in range(6):
            d[i] ^= mask
    else:  # even parity
        mask = d[5]
        for i in range(5):
            d[i] ^= mask
        d[6] ^= mask

    # Bit deinterleave bytes 5 and 6
    old5, old6 = d[5], d[6]
    d[5] = (old5 & 0xAA) | (old6 & 0x55)
    d[6] = (old5 & 0x55) | (old6 & 0xAA)

    # Checksum: sum of bytes 0-6 must equal byte 7
    checksum_ok = (sum(d[:7]) & 0xFF) == d[7]

    serial = (d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]
    button = d[4]
    counter = (d[5] << 8) | d[6]

    return {
        "serial": serial,
        "button": button,
        "counter": counter,
        "checksum_ok": checksum_ok,
    }


# ═══════════════════════════════════════════════════════════
# Security+ v1/v2 — Ternary encoding (LiftMaster/Chamberlain)
# Used by: LiftMaster, Chamberlain, Craftsman garage openers
# ═══════════════════════════════════════════════════════════

# Security+ v1: 42 bits split into 2x21, base-3 ternary
# Security+ v2: 62 bits, base-3 counter with 2^28 space


def secplus_v1_decode(packet1_trits, packet2_trits):
    """
    Security+ v1 ternary decode (Flipper-ARF algorithm).

    Two packets of 21 ternary digits each. Interleaves rolling
    and fixed codes with accumulator-based deobfuscation.

    Args:
        packet1_trits: list of 21 ternary digits (0/1/2) from packet 1
        packet2_trits: list of 21 ternary digits (0/1/2) from packet 2
    Returns:
        dict with rolling_code, fixed_code, button
    """
    rolling = 0
    fixed = 0

    for pkt_trits in [packet1_trits, packet2_trits]:
        acc = 0
        for i in range(0, 20, 2):
            d1 = pkt_trits[i + 1]  # rolling digit
            rolling = rolling * 3 + d1
            acc += d1

            d2 = (60 + pkt_trits[i + 2] - acc) % 3 if i + 2 < len(pkt_trits) else 0
            fixed = fixed * 3 + d2
            acc += d2

    # Bit-reverse rolling (32-bit)
    rev = 0
    tmp = rolling
    for _ in range(32):
        rev = (rev << 1) | (tmp & 1)
        tmp >>= 1
    rolling = rev

    button = fixed % 3
    return {
        "rolling_code": rolling,
        "fixed_code": fixed,
        "button": button,
    }


# Security+ v2 invert/order permutation tables
_SECV2_INVERT = {
    0x00: (True, True, False),
    0x01: (False, True, False),
    0x02: (False, False, True),
    0x04: (True, True, True),
    0x05: (True, False, True),
    0x06: (False, True, True),
    0x08: (True, False, False),
    0x09: (False, False, False),
    0x0A: (True, False, True),
}
_SECV2_ORDER = {
    0x02: (0, 1, 2),
    0x0A: (0, 1, 2),
    0x00: (0, 2, 1),
    0x05: (1, 0, 2),
    0x06: (2, 1, 0),
    0x09: (2, 1, 0),
    0x08: (1, 2, 0),
    0x04: (1, 2, 0),
    0x01: (2, 0, 1),
}


def secplus_v2_decode(data_62bit):
    """
    Security+ v2 decode (Flipper-ARF algorithm).

    62-bit Manchester payload with order/invert deobfuscation.

    Args:
        data_62bit: 62-bit captured half-message (int)
    Returns:
        dict with rolling_code, fixed_code, button
    """
    order = (data_62bit >> 34) & 0x0F
    invert = (data_62bit >> 30) & 0x0F
    payload = data_62bit & 0x3FFFFFFF

    # Deinterleave 30 bits into 3 x 10-bit values
    p = [0, 0, 0]
    for i in range(29, -1, -3):
        p[0] = (p[0] << 1) | ((payload >> i) & 1) if i >= 0 else p[0]
        p[1] = (p[1] << 1) | ((payload >> (i - 1)) & 1) if i - 1 >= 0 else p[1]
        p[2] = (p[2] << 1) | ((payload >> (i - 2)) & 1) if i - 2 >= 0 else p[2]

    # Selective inversion
    inv = _SECV2_INVERT.get(invert, (False, False, False))
    for i in range(3):
        if inv[i]:
            p[i] = (~p[i]) & 0x3FF

    # Reorder
    perm = _SECV2_ORDER.get(order, (0, 1, 2))
    p = [p[perm[0]], p[perm[1]], p[perm[2]]]

    fixed = (p[0] << 10) | p[1]
    # Rolling digits from order+invert nibbles + p[2]
    rolling = (order << 6) | (invert << 2) | (p[2] >> 8)

    return {
        "rolling_code": rolling,
        "fixed_code": fixed,
        "button": (fixed >> 12) & 0xF,
    }


# ═══════════════════════════════════════════════════════════
# Alutech AT-4N — Rainbow table block cipher
# Used by: Alutech AT-4N gate remotes (72-bit)
# ═══════════════════════════════════════════════════════════

ALUTECH_TABLE = [
    0x00,
    0x25,
    0x4A,
    0x6F,
    0x94,
    0xB1,
    0xDE,
    0xFB,
    0x22,
    0x07,
    0x68,
    0x4D,
    0xB6,
    0x93,
    0xFC,
    0xD9,
    0x44,
    0x61,
    0x0E,
    0x2B,
    0xD0,
    0xF5,
    0x9A,
    0xBF,
    0x66,
    0x43,
    0x2C,
    0x09,
    0xF2,
    0xD7,
    0xB8,
    0x9D,
]


def alutech_at4n_decrypt(data_bytes, serial):
    """
    Alutech AT-4N rainbow table cipher decrypt.

    Args:
        data_bytes: encrypted payload bytes
        serial: device serial
    Returns:
        list of decrypted bytes
    """
    k = (serial >> 8) & 0xFF
    out = list(data_bytes)
    for i in range(len(out)):
        out[i] ^= ALUTECH_TABLE[(k + i) & 0x1F]
    return out


# ═══════════════════════════════════════════════════════════
# PSA TEA brute-force modes
# Used by: PSA Peugeot/Citroen with two key derivation modes
# Mode 0x23: XOR with serial-derived key
# Mode 0x36: TEA encrypt with master key
# ═══════════════════════════════════════════════════════════


def psa_bruteforce_0x23(encrypted_v0, encrypted_v1, serial):
    """
    PSA brute-force mode 0x23: XOR with serial-derived key.
    Derives a 128-bit TEA key from serial, then decrypts.

    Args:
        encrypted_v0, encrypted_v1: 2x 32-bit encrypted blocks
        serial: 28-bit serial
    Returns:
        (v0, v1) decrypted, or None if failed
    """
    # Key derived from serial bytes XOR'd with 0x23
    s = [
        (serial >> 24) & 0xFF,
        (serial >> 16) & 0xFF,
        (serial >> 8) & 0xFF,
        serial & 0xFF,
    ]
    key = []
    for i in range(4):
        k32 = 0
        for j in range(4):
            k32 = (k32 << 8) | (s[(i + j) % 4] ^ 0x23)
        key.append(k32)
    return tea_decrypt(encrypted_v0, encrypted_v1, key)


def psa_bruteforce_0x36(encrypted_v0, encrypted_v1, serial):
    """
    PSA brute-force mode 0x36: TEA encrypt serial as key derivation.

    Args:
        encrypted_v0, encrypted_v1: 2x 32-bit encrypted blocks
        serial: 28-bit serial
    Returns:
        (v0, v1) decrypted, or None if failed
    """
    # Derive key by TEA-encrypting serial with itself
    s = [
        (serial >> 24) & 0xFF,
        (serial >> 16) & 0xFF,
        (serial >> 8) & 0xFF,
        serial & 0xFF,
    ]
    seed_v0 = (s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3]
    seed_v1 = seed_v0 ^ 0x36363636
    master_key = [seed_v0, seed_v1, seed_v0 ^ 0xFF, seed_v1 ^ 0xFF]
    # Encrypt seed to derive actual key
    dk0, dk1 = tea_encrypt(seed_v0, seed_v1, master_key)
    dk2, dk3 = tea_encrypt(seed_v1, seed_v0, master_key)
    derived_key = [dk0, dk1, dk2, dk3]
    return tea_decrypt(encrypted_v0, encrypted_v1, derived_key)


# ═══════════════════════════════════════════════════════════
# KIA V3/V4 — KeeLoq with known master key
# Master key: 0xA8F5DFFC8DAA5CDB (from Flipper-ARF)
# ═══════════════════════════════════════════════════════════

KIA_V3_V4_MASTER_KEY = 0xA8F5DFFC8DAA5CDB


def kia_v3_v4_derive_key(serial):
    """
    Derive KIA V3/V4 device key from serial using master key.

    Args:
        serial: 28-bit serial
    Returns:
        64-bit device key
    """
    from urh.util.KeeLoq import encrypt as keeloq_encrypt

    # Normal learning: encrypt serial LSBs with master key
    lsb16 = serial & 0xFFFF
    msb16 = (serial >> 16) & 0x0FFF
    hop_low = keeloq_encrypt(lsb16 | 0x20000000, KIA_V3_V4_MASTER_KEY)
    hop_high = keeloq_encrypt(msb16 | 0x60000000, KIA_V3_V4_MASTER_KEY)
    return (hop_high << 32) | hop_low


def kia_v3_v4_decrypt(encrypted, serial):
    """
    KIA V3/V4 KeeLoq decrypt.

    Args:
        encrypted: 32-bit encrypted hop code
        serial: 28-bit serial
    Returns:
        dict with counter, button, disc
    """
    from urh.util.KeeLoq import decrypt as keeloq_decrypt

    device_key = kia_v3_v4_derive_key(serial)
    decrypted = keeloq_decrypt(encrypted, device_key)
    button = (decrypted >> 28) & 0x0F
    disc = (decrypted >> 16) & 0x3FF
    counter = decrypted & 0xFFFF
    return {"counter": counter, "button": button, "disc": disc}


# ═══════════════════════════════════════════════════════════
# KIA V6 — AES-128 ECB with specific key derivation
# Key: XOR masks 0x84AF25FB / 0x638766AB + keystore XOR
# ═══════════════════════════════════════════════════════════

# KIA V6 hardcoded AES key (derived from Flipper-ARF constants)
KIA_V6_AES_KEY = [
    0x00,
    0x01,
    0x02,
    0x13,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0A,
    0x1B,
    0x0C,
    0x0D,
    0x0E,
    0x0F,
]


def kia_v6_decrypt(ciphertext_bytes, aes_key=None):
    """
    KIA V6 AES-128 ECB decrypt (Flipper-ARF algorithm).

    Uses hardcoded AES key derived at compile-time from XOR constants.

    Args:
        ciphertext_bytes: 16-byte ciphertext (list of ints)
        aes_key: optional 16-byte key override (default: KIA_V6_AES_KEY)
    Returns:
        dict with serial, counter, button, crc_ok
    """
    if aes_key is None:
        aes_key = KIA_V6_AES_KEY

    plaintext = aes128_decrypt(ciphertext_bytes, aes_key)

    serial = (plaintext[4] << 16) | (plaintext[5] << 8) | plaintext[6]
    button = plaintext[7]
    counter = (
        (plaintext[8] << 24)
        | (plaintext[9] << 16)
        | (plaintext[10] << 8)
        | plaintext[11]
    )
    # CRC integrity: plaintext[12] should equal AES S-box[counter & 0xFF]
    sbox_check = AES_SBOX[counter & 0xFF]
    crc1_ok = plaintext[12] == sbox_check

    # CRC-8 over first 15 bytes (init=0xFF, poly=0x07)
    crc8_calc = 0xFF
    for b in plaintext[:15]:
        crc8_calc ^= b
        for _ in range(8):
            if crc8_calc & 0x80:
                crc8_calc = ((crc8_calc << 1) ^ 0x07) & 0xFF
            else:
                crc8_calc = (crc8_calc << 1) & 0xFF
    crc2_ok = abs(crc8_calc - plaintext[15]) < 2

    return {
        "serial": serial,
        "button": button,
        "counter": counter,
        "crc_ok": crc1_ok and crc2_ok,
        "plaintext": plaintext,
    }


# ═══════════════════════════════════════════════════════════
# FAAC SLH — KeeLoq with FAAC-specific learning mode
# ═══════════════════════════════════════════════════════════


def faac_slh_derive_key(serial, seed, manufacturer_key):
    """
    FAAC SLH KeeLoq key derivation.

    Args:
        serial: 28-bit serial
        seed: 32-bit seed
        manufacturer_key: 64-bit FAAC manufacturer key
    Returns:
        64-bit device key
    """
    from urh.util.KeeLoq import encrypt as keeloq_encrypt

    # FAAC SLH: encrypt seed with manufacturer key
    hop_low = keeloq_encrypt(seed & 0xFFFFFFFF, manufacturer_key)
    hop_high = keeloq_encrypt((seed >> 16) | (serial << 16), manufacturer_key)
    return (hop_high << 32) | hop_low


# ═══════════════════════════════════════════════════════════
# VAG full protocol — AUT64 (Types 1/3) + TEA (Types 2/4)
# ═══════════════════════════════════════════════════════════


# VAG hardcoded AUT64 keys (from Flipper-ARF vag.c, 3 key sets)
VAG_AUT64_KEYS = [
    # Key 0 (type 1)
    [
        0x01,
        0x37,
        0x6C,
        0x86,
        0xAD,
        0xAB,
        0xCC,
        0x43,
        0x07,
        0x4D,
        0xE8,
        0x59,
        0xC1,
        0x2F,
        0x36,
        0xAB,
    ],
    # Key 1 (type 1)
    [
        0x02,
        0x37,
        0x7C,
        0x65,
        0xCE,
        0xDC,
        0x42,
        0xEA,
        0xA4,
        0x53,
        0xE8,
        0x61,
        0xD9,
        0xB7,
        0x20,
        0xFC,
    ],
    # Key 2 (type 3/4)
    [
        0x03,
        0x8A,
        0xA3,
        0x7B,
        0x1E,
        0x56,
        0x1F,
        0x83,
        0x84,
        0xB6,
        0x19,
        0xC5,
        0x2E,
        0x0A,
        0x3F,
        0xD7,
    ],
]
# VAG TEA key schedule
VAG_TEA_KEY = [0x0B46502D, 0x5E253718, 0x2BF93A19, 0x622C1206]

VAG_BUTTON_MAP = {0x10: "Unlock", 0x20: "Lock", 0x40: "Trunk", 0x80: "Panic"}
VAG_TYPE_NAMES = {
    0x00: "VAG NEW",
    0xC0: "VAG OLD",
    0xC1: "AUDI",
    0xC2: "SEAT",
    0xC3: "SKODA",
}
VAG_DISPATCH_T12 = {0x2A: 0x20, 0x1C: 0x10, 0x46: 0x40, 0x88: 0x80}
VAG_DISPATCH_T34 = {0x2B: 0x20, 0x1D: 0x10, 0x47: 0x40, 0x89: 0x80}


def vag_decode(key1_64bit, key2_16bit):
    """
    Full VAG protocol decode (Flipper-ARF algorithm).

    Tries all 4 types (AUT64 x3 keys + TEA) and returns the first
    valid decryption.

    Args:
        key1_64bit: 64-bit key1 from Manchester-decoded data
        key2_16bit: 16-bit key2 from Manchester-decoded data
    Returns:
        dict with serial, counter, button, button_name, vag_type,
              vehicle_type, key_index, or error
    """
    type_byte = (key1_64bit >> 56) & 0xFF
    vehicle = VAG_TYPE_NAMES.get(type_byte, "VAG GEN")

    # Build 8-byte block: key1_bytes[1..7] + key2_high
    k1_bytes = [(key1_64bit >> (56 - i * 8)) & 0xFF for i in range(8)]
    block = k1_bytes[1:8] + [(key2_16bit >> 8) & 0xFF]
    dispatch = key2_16bit & 0xFF

    # Try AUT64 with all 3 keys
    for ki, packed in enumerate(VAG_AUT64_KEYS):
        uk = aut64_unpack(packed)
        test = list(block)
        dec = aut64_decrypt(test, uk["key"], uk["sbox"], uk["pbox"])

        btn_nib = (dec[7] >> 4) & 0xF
        if btn_nib in (1, 2, 4, 8):
            btn = btn_nib << 4
            # Validate dispatch
            valid_dispatch = VAG_DISPATCH_T12 if ki < 2 else VAG_DISPATCH_T34
            if dispatch in valid_dispatch:
                serial_raw = dec[0] | (dec[1] << 8) | (dec[2] << 16) | (dec[3] << 24)
                serial = (
                    ((serial_raw >> 24) & 0xFF)
                    | (((serial_raw >> 16) & 0xFF) << 8)
                    | (((serial_raw >> 8) & 0xFF) << 16)
                    | ((serial_raw & 0xFF) << 24)
                )
                counter = dec[4] | (dec[5] << 8) | (dec[6] << 16)
                vtype = 4 if ki == 2 else (3 if ki >= 1 else 1)
                return {
                    "serial": serial,
                    "counter": counter,
                    "button": btn,
                    "button_name": VAG_BUTTON_MAP.get(btn, f"0x{btn:02X}"),
                    "vag_type": vtype,
                    "vehicle_type": vehicle,
                    "key_index": uk["index"],
                    "cipher": "AUT64",
                }

    # Try TEA
    v0 = (block[0] << 24) | (block[1] << 16) | (block[2] << 8) | block[3]
    v1 = (block[4] << 24) | (block[5] << 16) | (block[6] << 8) | block[7]
    d0, d1 = tea_decrypt(v0, v1, VAG_TEA_KEY)
    tea_dec = [
        (d0 >> 24) & 0xFF,
        (d0 >> 16) & 0xFF,
        (d0 >> 8) & 0xFF,
        d0 & 0xFF,
        (d1 >> 24) & 0xFF,
        (d1 >> 16) & 0xFF,
        (d1 >> 8) & 0xFF,
        d1 & 0xFF,
    ]
    btn_nib = (tea_dec[7] >> 4) & 0xF
    if btn_nib in (1, 2, 4, 8) and dispatch in VAG_DISPATCH_T12:
        btn = btn_nib << 4
        serial_raw = (
            tea_dec[0] | (tea_dec[1] << 8) | (tea_dec[2] << 16) | (tea_dec[3] << 24)
        )
        serial = (
            ((serial_raw >> 24) & 0xFF)
            | (((serial_raw >> 16) & 0xFF) << 8)
            | (((serial_raw >> 8) & 0xFF) << 16)
            | ((serial_raw & 0xFF) << 24)
        )
        counter = tea_dec[4] | (tea_dec[5] << 8) | (tea_dec[6] << 16)
        return {
            "serial": serial,
            "counter": counter,
            "button": btn,
            "button_name": VAG_BUTTON_MAP.get(btn, f"0x{btn:02X}"),
            "vag_type": 2,
            "vehicle_type": vehicle,
            "key_index": 0,
            "cipher": "TEA",
        }

    return {"error": "No valid key found", "vehicle_type": vehicle}


def vag_decrypt(
    encrypted_v0,
    encrypted_v1,
    key,
    vag_type=2,
    sbox=None,
    pbox=None,
):
    """
    VAG (VW/Audi/Skoda/Seat) decrypt.

    Args:
        encrypted_v0, encrypted_v1: 2x 32-bit encrypted blocks
        key: key bytes (8 bytes for AUT64, 16 bytes/4x32 for TEA)
        vag_type: 1 or 3 = AUT64, 2 or 4 = TEA
        sbox: 256-byte S-box for AUT64 (vehicle-specific)
        pbox: 8-byte P-box for AUT64 (vehicle-specific)
    Returns:
        (v0, v1) decrypted
    """
    if vag_type in (1, 3):
        if sbox is None:
            sbox = _VAG_DEFAULT_SBOX
        if pbox is None:
            pbox = _VAG_DEFAULT_PBOX
        block = [
            (encrypted_v0 >> 24) & 0xFF,
            (encrypted_v0 >> 16) & 0xFF,
            (encrypted_v0 >> 8) & 0xFF,
            encrypted_v0 & 0xFF,
            (encrypted_v1 >> 24) & 0xFF,
            (encrypted_v1 >> 16) & 0xFF,
            (encrypted_v1 >> 8) & 0xFF,
            encrypted_v1 & 0xFF,
        ]
        result = aut64_decrypt(block, list(key), sbox, pbox)
        v0 = (result[0] << 24) | (result[1] << 16) | (result[2] << 8) | result[3]
        v1 = (result[4] << 24) | (result[5] << 16) | (result[6] << 8) | result[7]
        return v0, v1
    else:
        tea_key = (
            list(key)
            if len(key) == 4
            else [
                (key[i * 4] << 24)
                | (key[i * 4 + 1] << 16)
                | (key[i * 4 + 2] << 8)
                | key[i * 4 + 3]
                for i in range(4)
            ]
        )
        return tea_decrypt(encrypted_v0, encrypted_v1, tea_key)


# ═══════════════════════════════════════════════════════════
# Available ciphers registry
# ═══════════════════════════════════════════════════════════

CIPHER_INFO = {
    "TEA": {
        "name": "TEA (Tiny Encryption Algorithm)",
        "key_bits": 128,
        "block_bits": 64,
        "used_by": "PSA Peugeot/Citroen, VAG VW/Audi (Types 2/4)",
    },
    "AES-128": {
        "name": "AES-128",
        "key_bits": 128,
        "block_bits": 128,
        "used_by": "KIA V6, Hyundai, Beninca ARC",
    },
    "AUT64": {
        "name": "AUT64",
        "key_bits": 64,
        "block_bits": 64,
        "used_by": "VAG VW/Audi (Types 1/3, older)",
    },
    "KIA-V5-Mixer": {
        "name": "KIA V5 Mixer Cipher",
        "key_bits": 64,
        "block_bits": 32,
        "used_by": "KIA V5",
    },
    "KIA-V3-V4": {
        "name": "KIA V3/V4 KeeLoq",
        "key_bits": 64,
        "block_bits": 32,
        "used_by": "KIA V3, KIA V4, Hyundai",
        "master_key": "0xA8F5DFFC8DAA5CDB",
    },
    "KIA-V6-AES": {
        "name": "KIA V6 AES-128",
        "key_bits": 128,
        "block_bits": 128,
        "used_by": "KIA V6 (XOR mask key derivation)",
    },
    "Mitsubishi-XOR": {
        "name": "Mitsubishi V0 XOR Scrambling",
        "key_bits": 16,
        "block_bits": 64,
        "used_by": "Mitsubishi V0",
    },
    "Ford-GF2-CRC": {
        "name": "Ford V0 Protocol Decoder",
        "key_bits": 0,
        "block_bits": 80,
        "used_by": "Ford V0 (XOR obfuscation + bit interleave + GF(2) CRC)",
        "functions": "ford_v0_decode, ford_v0_encode, ford_v0_decode_bits",
    },
    "KeeLoq": {
        "name": "KeeLoq",
        "key_bits": 64,
        "block_bits": 32,
        "used_by": (
            "HCS200/300, FAAC, NICE, StarLine, Sheriff, "
            "KingGates, Jarolift, many gates"
        ),
    },
    "FAAC-SLH": {
        "name": "FAAC SLH KeeLoq",
        "key_bits": 64,
        "block_bits": 32,
        "used_by": "FAAC SLH (seed-based KeeLoq)",
    },
    "Nice-FlorS": {
        "name": "Nice Flor-S",
        "key_bits": 0,
        "block_bits": 52,
        "used_by": "NICE Flor-S (rainbow table + XOR)",
    },
    "Somfy-XOR": {
        "name": "Somfy Telis/Keytis XOR",
        "key_bits": 0,
        "block_bits": 56,
        "used_by": "Somfy Telis (56b), Somfy Keytis (80b)",
    },
    "Came-Atomo": {
        "name": "Came Atomo XOR",
        "key_bits": 0,
        "block_bits": 62,
        "used_by": "Came Atomo",
    },
    "Came-Twee": {
        "name": "Came Twee XOR",
        "key_bits": 0,
        "block_bits": 54,
        "used_by": "Came Twee (rainbow table XOR)",
    },
    "Scher-Khan": {
        "name": "Scher-Khan Pi-XOR",
        "key_bits": 0,
        "block_bits": 72,
        "used_by": "Scher-Khan Magicar",
    },
    "Phoenix-V2": {
        "name": "Phoenix V2 Bit-Shuffle",
        "key_bits": 20,
        "block_bits": 32,
        "used_by": "Phoenix V2",
    },
    "Porsche-Cayenne": {
        "name": "Porsche Cayenne Rotating Register",
        "key_bits": 24,
        "block_bits": 32,
        "used_by": "Porsche Cayenne",
    },
    "Subaru-XOR": {
        "name": "Subaru Rotating XOR",
        "key_bits": 32,
        "block_bits": 32,
        "used_by": "Subaru",
    },
    "Mazda-Siemens": {
        "name": "Mazda Siemens Parity-XOR",
        "key_bits": 28,
        "block_bits": 32,
        "used_by": "Mazda (Siemens)",
    },
    "SecurityPlus": {
        "name": "Security+ v1/v2 Ternary",
        "key_bits": 0,
        "block_bits": 42,
        "used_by": "LiftMaster, Chamberlain, Craftsman",
    },
    "PSA-TEA": {
        "name": "PSA TEA (brute-force modes)",
        "key_bits": 128,
        "block_bits": 64,
        "used_by": "PSA Peugeot/Citroen (0x23 XOR + 0x36 TEA)",
    },
    "Alutech-AT4N": {
        "name": "Alutech AT-4N Rainbow",
        "key_bits": 0,
        "block_bits": 72,
        "used_by": "Alutech AT-4N",
    },
    "VAG": {
        "name": "VAG Full Protocol",
        "key_bits": 128,
        "block_bits": 64,
        "used_by": "VAG VW/Audi/Skoda/Seat (AUT64 + TEA)",
    },
}
