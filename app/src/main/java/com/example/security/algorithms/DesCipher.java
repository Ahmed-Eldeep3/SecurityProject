package com.example.security.algorithms;

import com.example.security.base.CipherAlgorithm;

import java.nio.charset.StandardCharsets;

public class DesCipher implements CipherAlgorithm {


    private static final int[] IP = {
            58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
            57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7
    };

    private static final int[] IP_INV = {
            40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
            38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
            36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
            34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25
    };

    private static final int[] E = {
            32,1,2,3,4,5, 4,5,6,7,8,9, 8,9,10,11,12,13,
            12,13,14,15,16,17, 16,17,18,19,20,21, 20,21,22,23,24,25,
            24,25,26,27,28,29, 28,29,30,31,32,1
    };

    private static final int[] P = {
            16,7,20,21,29,12,28,17, 1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9,  19,13,30,6,22,11,4,25
    };

    private static final int[] PC1 = {
            57,49,41,33,25,17,9,  1,58,50,42,34,26,18,
            10, 2,59,51,43,35,27, 19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
            14, 6,61,53,45,37,29, 21,13,5,28,20,12,4
    };

    private static final int[] PC2 = {
            14,17,11,24,1,5,  3,28,15,6,21,10,
            23,19,12,4,26,8, 16,7,27,20,13,2,
            41,52,31,37,47,55, 30,40,51,45,33,48,
            44,49,39,56,34,53, 46,42,50,36,29,32
    };

    private static final int[] SHIFTS = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

    private static final int[][][] SBOX = {
            // S1
            {{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
                    {  0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
                    {  4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
                    { 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }},
            // S2
            {{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
                    {  3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
                    {  0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
                    { 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }},
            // S3
            {{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
                    { 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
                    { 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
                    {  1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }},
            // S4
            {{  7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
                    { 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
                    { 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
                    {  3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }},
            // S5
            {{  2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
                    { 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
                    {  4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
                    { 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }},
            // S6
            {{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
                    { 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
                    {  9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
                    {  4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }},
            // S7
            {{  4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
                    { 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
                    {  1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
                    {  6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }},
            // S8
            {{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
                    {  1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
                    {  7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
                    {  2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }}
    };


    private long[] generateSubkeys(byte[] keyBytes) {
        long key64 = bytesToLong(keyBytes);

        long key56 = permute(key64, PC1, 64);

        long C = (key56 >>> 28) & 0xFFFFFFFL;
        long D =  key56         & 0xFFFFFFFL;

        long[] subkeys = new long[16];
        for (int i = 0; i < 16; i++) {

            C = circShift28(C, SHIFTS[i]);
            D = circShift28(D, SHIFTS[i]);

            long CD = (C << 28) | D;
            subkeys[i] = permute(CD, PC2, 56);
        }
        return subkeys;
    }


    private long feistel(long R, long subkey) {

        long expanded = permute(R, E, 32);

        long xored = expanded ^ subkey;

        long sboxOut = 0;
        for (int i = 0; i < 8; i++) {
            int chunk  = (int) ((xored >>> (42 - 6*i)) & 0x3F);
            int row    = ((chunk & 0x20) >> 4) | (chunk & 0x01);
            int col    = (chunk >> 1) & 0x0F;
            int sval   = SBOX[i][row][col];
            sboxOut    = (sboxOut << 4) | sval;
        }

        return permute(sboxOut, P, 32);
    }

    private long processBlock(long block, long[] subkeys) {

        long permuted = permute(block, IP, 64);

        long L = (permuted >>> 32) & 0xFFFFFFFFL;
        long R =  permuted         & 0xFFFFFFFFL;

        for (int i = 0; i < 16; i++) {
            long newR = L ^ feistel(R, subkeys[i]);
            L = R;
            R = newR;
        }

        long combined = (R << 32) | L;
        return permute(combined, IP_INV, 64);
    }


    @Override
    public String encrypt(String plainText, String key) throws Exception {
        byte[] keyBytes   = prepareKey(key);
        byte[] data       = pkcs8Pad(plainText.getBytes(StandardCharsets.UTF_8));
        long[] subkeys    = generateSubkeys(keyBytes);

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 8) {
            long block    = bytesToLong(data, i);
            long cipher   = processBlock(block, subkeys);
            sb.append(longToHex(cipher));
        }
        return sb.toString();
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        byte[] keyBytes  = prepareKey(key);
        byte[] data      = hexToBytes(cipherText.trim());
        long[] subkeys   = generateSubkeys(keyBytes);

        long[] revKeys = new long[16];
        for (int i = 0; i < 16; i++) revKeys[i] = subkeys[15 - i];

        byte[] result = new byte[data.length];
        for (int i = 0; i < data.length; i += 8) {
            long block   = bytesToLong(data, i);
            long plain   = processBlock(block, revKeys);
            longToBytes(plain, result, i);
        }
        return new String(pkcs8Unpad(result), StandardCharsets.UTF_8);
    }


    private long permute(long input, int[] table, int inputBits) {
        long out = 0;
        for (int i = 0; i < table.length; i++) {
            int bitPos = inputBits - table[i];
            long bit   = (input >>> bitPos) & 1L;
            out        = (out << 1) | bit;
        }
        return out;
    }

    private long circShift28(long val, int n) {
        return ((val << n) | (val >>> (28 - n))) & 0xFFFFFFFL;
    }

    private long bytesToLong(byte[] b) {
        return bytesToLong(b, 0);
    }

    private long bytesToLong(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++)
            v = (v << 8) | (b[off + i] & 0xFF);
        return v;
    }

    private void longToBytes(long v, byte[] out, int off) {
        for (int i = 7; i >= 0; i--) { out[off + i] = (byte)(v & 0xFF); v >>= 8; }
    }

    private String longToHex(long v) {
        return String.format("%016X", v);
    }


    private byte[] pkcs8Pad(byte[] data) {
        int pad = 8 - (data.length % 8);
        byte[] out = new byte[data.length + pad];
        System.arraycopy(data, 0, out, 0, data.length);
        for (int i = data.length; i < out.length; i++) out[i] = (byte) pad;
        return out;
    }

    private byte[] pkcs8Unpad(byte[] data) throws Exception {
        if (data.length == 0 || data.length % 8 != 0)
            throw new Exception("Invalid DES data length.");
        int pad = data[data.length - 1] & 0xFF;
        if (pad < 1 || pad > 8) throw new Exception("Invalid padding.");
        byte[] out = new byte[data.length - pad];
        System.arraycopy(data, 0, out, 0, out.length);
        return out;
    }


    private byte[] prepareKey(String key) throws Exception {
        byte[] raw = key.getBytes(StandardCharsets.UTF_8);
        if (raw.length > 8) throw new Exception("Key max 8 characters for DES.");
        byte[] out = new byte[8];
        System.arraycopy(raw, 0, out, 0, raw.length);
        return out;
    }

    private byte[] hexToBytes(String hex) throws Exception {
        hex = hex.replaceAll("\\s+", "");
        if (hex.length() % 2 != 0) throw new Exception("Invalid hex.");
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++)
            out[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        return out;
    }

    @Override public String  getAlgorithmName() { return "DES"; }
    @Override public String  getKeyHint()        { return "Key: max 8 characters  (e.g. MYKEY123)"; }
    @Override public boolean requiresKey()       { return true; }
}
