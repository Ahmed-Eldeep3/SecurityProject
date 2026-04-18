package com.example.security.base;

public interface CipherAlgorithm {
    String encrypt(String plainText, String key) throws Exception;
    String decrypt(String cipherText, String key) throws Exception;
    String getAlgorithmName();
    String getKeyHint();
    boolean requiresKey();
}
