package com.example.security.algorithms;

import com.example.security.base.CipherAlgorithm;

import java.nio.charset.StandardCharsets;


public class AesCipher implements CipherAlgorithm {

    private static final int[] SBOX = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    private static final int[] INV_SBOX = {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };


    private static final int[] RCON = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    private int gmul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) p ^= a;
            boolean hiBit = (a & 0x80) != 0;
            a = (a << 1) & 0xFF;
            if (hiBit) a ^= 0x1b;   // reduction polynomial
            b >>= 1;
        }
        return p & 0xFF;
    }



    private int[][] keyExpansion(byte[] key) throws Exception {
        if (key.length != 16)
            throw new Exception("AES-128 requires exactly 16 bytes (128-bit) key.");

        int[] w = new int[44];

        for (int i = 0; i < 4; i++) {
            w[i] = ((key[4*i]   & 0xFF) << 24)
                    | ((key[4*i+1] & 0xFF) << 16)
                    | ((key[4*i+2] & 0xFF) << 8)
                    |  (key[4*i+3] & 0xFF);
        }

        for (int i = 4; i < 44; i++) {
            int temp = w[i - 1];

            if (i % 4 == 0) {
                temp = ((temp << 8) | (temp >>> 24));
                temp = Integer.rotateLeft(temp, 8);

                temp = (SBOX[(temp >>> 24) & 0xFF] << 24)
                        | (SBOX[(temp >>> 16) & 0xFF] << 16)
                        | (SBOX[(temp >>>  8) & 0xFF] << 8)
                        |  SBOX[ temp         & 0xFF];

                temp ^= (RCON[i / 4] << 24);
            }

            w[i] = w[i - 4] ^ temp;
        }

        int[][] roundKeys = new int[11][4];
        for (int round = 0; round < 11; round++) {
            for (int col = 0; col < 4; col++) {
                roundKeys[round][col] = w[round * 4 + col];
            }
        }
        return roundKeys;
    }

    private void subBytes(int[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = SBOX[state[r][c] & 0xFF];
    }

    private void invSubBytes(int[][] state) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = INV_SBOX[state[r][c] & 0xFF];
    }


    private void shiftRows(int[][] state) {
        for (int r = 1; r < 4; r++) {
            int[] temp = new int[4];
            for (int c = 0; c < 4; c++)
                temp[c] = state[r][(c + r) % 4];
            state[r] = temp;
        }
    }

    private void invShiftRows(int[][] state) {
        for (int r = 1; r < 4; r++) {
            int[] temp = new int[4];
            for (int c = 0; c < 4; c++)
                temp[c] = state[r][(c - r + 4) % 4];
            state[r] = temp;
        }
    }


    private void mixColumns(int[][] state) {
        for (int c = 0; c < 4; c++) {
            int a0 = state[0][c], a1 = state[1][c],
                    a2 = state[2][c], a3 = state[3][c];

            state[0][c] = gmul(2,a0) ^ gmul(3,a1) ^ a2       ^ a3;
            state[1][c] = a0         ^ gmul(2,a1) ^ gmul(3,a2)^ a3;
            state[2][c] = a0         ^ a1          ^ gmul(2,a2)^ gmul(3,a3);
            state[3][c] = gmul(3,a0) ^ a1          ^ a2        ^ gmul(2,a3);
        }
    }


    private void invMixColumns(int[][] state) {
        for (int c = 0; c < 4; c++) {
            int a0 = state[0][c], a1 = state[1][c],
                    a2 = state[2][c], a3 = state[3][c];

            state[0][c] = gmul(14,a0)^ gmul(11,a1)^ gmul(13,a2)^ gmul(9, a3);
            state[1][c] = gmul(9, a0)^ gmul(14,a1)^ gmul(11,a2)^ gmul(13,a3);
            state[2][c] = gmul(13,a0)^ gmul(9, a1)^ gmul(14,a2)^ gmul(11,a3);
            state[3][c] = gmul(11,a0)^ gmul(13,a1)^ gmul(9, a2)^ gmul(14,a3);
        }
    }


    private void addRoundKey(int[][] state, int[] roundKey) {
        for (int c = 0; c < 4; c++) {
            int word = roundKey[c];
            state[0][c] ^= (word >>> 24) & 0xFF;
            state[1][c] ^= (word >>> 16) & 0xFF;
            state[2][c] ^= (word >>>  8) & 0xFF;
            state[3][c] ^=  word         & 0xFF;
        }
    }


    private int[][] bytesToState(byte[] block) {
        int[][] state = new int[4][4];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                state[r][c] = block[c * 4 + r] & 0xFF;
        return state;
    }

    private byte[] stateToBytes(int[][] state) {
        byte[] out = new byte[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++)
                out[c * 4 + r] = (byte) state[r][c];
        return out;
    }


    private byte[] pkcs7Pad(byte[] data) {
        int padLen = 16 - (data.length % 16);
        byte[] padded = new byte[data.length + padLen];
        System.arraycopy(data, 0, padded, 0, data.length);
        for (int i = data.length; i < padded.length; i++)
            padded[i] = (byte) padLen;
        return padded;
    }

    private byte[] pkcs7Unpad(byte[] data) throws Exception {
        if (data.length == 0 || data.length % 16 != 0)
            throw new Exception("Invalid data length for AES.");
        int padLen = data[data.length - 1] & 0xFF;
        if (padLen < 1 || padLen > 16)
            throw new Exception("Invalid padding.");
        byte[] unpadded = new byte[data.length - padLen];
        System.arraycopy(data, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }


    private byte[] encryptBlock(byte[] block, int[][] roundKeys) {
        int[][] state = bytesToState(block);

        // Initial Round
        addRoundKey(state, roundKeys[0]);

        // Rounds 1 – 9
        for (int round = 1; round <= 9; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }

        // Round 10 — no MixColumns
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[10]);

        return stateToBytes(state);
    }


    private byte[] decryptBlock(byte[] block, int[][] roundKeys) {
        int[][] state = bytesToState(block);

        addRoundKey(state, roundKeys[10]);
        invShiftRows(state);
        invSubBytes(state);

        for (int round = 9; round >= 1; round--) {
            addRoundKey(state, roundKeys[round]);
            invMixColumns(state);
            invShiftRows(state);
            invSubBytes(state);
        }

        addRoundKey(state, roundKeys[0]);

        return stateToBytes(state);
    }


    @Override
    public String encrypt(String plainText, String key) throws Exception {
        byte[] keyBytes   = prepareKey(key);
        byte[] textBytes  = pkcs7Pad(plainText.getBytes(StandardCharsets.UTF_8));
        int[][] roundKeys = keyExpansion(keyBytes);

        byte[] result = new byte[textBytes.length];
        for (int i = 0; i < textBytes.length; i += 16) {
            byte[] block = new byte[16];
            System.arraycopy(textBytes, i, block, 0, 16);
            byte[] enc = encryptBlock(block, roundKeys);
            System.arraycopy(enc, 0, result, i, 16);
        }
        return bytesToHex(result);
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        byte[] keyBytes   = prepareKey(key);
        byte[] cipherBytes = hexToBytes(cipherText.trim());
        int[][] roundKeys = keyExpansion(keyBytes);

        byte[] result = new byte[cipherBytes.length];
        for (int i = 0; i < cipherBytes.length; i += 16) {
            byte[] block = new byte[16];
            System.arraycopy(cipherBytes, i, block, 0, 16);
            byte[] dec = decryptBlock(block, roundKeys);
            System.arraycopy(dec, 0, result, i, 16);
        }
        return new String(pkcs7Unpad(result), StandardCharsets.UTF_8);
    }


    private byte[] prepareKey(String key) throws Exception {
        byte[] raw = key.getBytes(StandardCharsets.UTF_8);
        if (raw.length > 16)
            throw new Exception("Key too long. Max 16 characters for AES-128.");
        byte[] out = new byte[16]; // zero-filled
        System.arraycopy(raw, 0, out, 0, raw.length);
        return out;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes)
            sb.append(String.format("%02X", b & 0xFF));
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) throws Exception {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0)
            throw new Exception("Invalid HEX string.");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return out;
    }

    // ── Metadata ──────────────────────────────────────────────────

    @Override public String getAlgorithmName() { return "AES-128 (Manual)"; }
    @Override public String getKeyHint()        { return "Key: max 16 characters (AES-128)"; }
    @Override public boolean requiresKey()      { return true; }
}