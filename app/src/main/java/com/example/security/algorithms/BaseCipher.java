package com.example.security.algorithms;

import com.example.security.base.CipherAlgorithm;


public abstract class BaseCipher implements CipherAlgorithm {


    protected String normalizeLettersKey(String key) throws Exception {
        String k = key.trim().toLowerCase();
        if (k.isEmpty())
            throw new Exception("Key cannot be empty.");
        if (!k.matches("[a-z]+"))
            throw new Exception("Key must contain letters only (a–z).");
        return k;
    }


    protected char shiftChar(char c, int shift) {
        char base = Character.isUpperCase(c) ? 'A' : 'a';
        return (char) ((c - base + shift % 26 + 26) % 26 + base);
    }

    protected int charIndex(char c) {
        return Character.toLowerCase(c) - 'a';
    }
}
