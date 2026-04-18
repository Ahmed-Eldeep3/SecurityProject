package com.example.security.algorithms;

import com.example.security.base.CipherAlgorithm;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;


public class RsaCipher implements CipherAlgorithm {

    private static final BigInteger E        = BigInteger.valueOf(65537);
    private static final int        KEY_BITS = 512;

    private static final String SEPARATOR    = "|||";
    private static final String PRIVATE_LABEL = "\n\n[PRIVATE KEY - copy for decrypt]: ";


    @Override
    public String encrypt(String plainText, String key) throws Exception {
        // توليد key pair من الـ seed
        SecureRandom rng = new SecureRandom(toSeedBytes(key));
        BigInteger p     = BigInteger.probablePrime(KEY_BITS / 2, rng);
        BigInteger q     = BigInteger.probablePrime(KEY_BITS / 2, rng);
        BigInteger n     = p.multiply(q);
        BigInteger phi   = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger d     = E.modInverse(phi);

        byte[] bytes     = plainText.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            BigInteger m = BigInteger.valueOf(b & 0xFF);
            BigInteger c = m.modPow(E, n);
            sb.append(c.toString(16)).append(",");
        }
        if (sb.length() > 0) sb.deleteCharAt(sb.length() - 1);

        return sb.toString()
                + PRIVATE_LABEL
                + n.toString(16) + ":" + d.toString(16);
    }


    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        String[] kp = key.trim().split(":");
        if (kp.length != 2)
            throw new Exception(
                    "Key must be in format  n:d\n" +
                            "Copy it from the encrypt result.");

        BigInteger n = new BigInteger(kp[0].trim(), 16);
        BigInteger d = new BigInteger(kp[1].trim(), 16);

        String cipher = cipherText.contains(PRIVATE_LABEL)
                ? cipherText.substring(0, cipherText.indexOf(PRIVATE_LABEL)).trim()
                : cipherText.trim();

        String[] parts = cipher.split(",");
        byte[] decrypted = new byte[parts.length];
        for (int i = 0; i < parts.length; i++) {
            BigInteger c = new BigInteger(parts[i].trim(), 16);
            decrypted[i] = c.modPow(d, n).byteValueExact();
        }
        return new String(decrypted, StandardCharsets.UTF_8);
    }


    private byte[] toSeedBytes(String s) {
        byte[] raw = s.getBytes();
        byte[] seed = new byte[Math.max(raw.length, 8)];
        System.arraycopy(raw, 0, seed, 0, raw.length);
        return seed;
    }

    @Override public String  getAlgorithmName() { return "RSA"; }
    @Override public String  getKeyHint()        { return "Encrypt: any word | Decrypt: paste  n:d  from result"; }
    @Override public boolean requiresKey()       { return true; }
}
