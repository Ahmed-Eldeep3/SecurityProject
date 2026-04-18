package com.example.security.algorithms;


public class CaesarCipher extends BaseCipher {

    @Override
    public String encrypt(String plainText, String key) throws Exception {
        return process(plainText, parseShift(key));
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        return process(cipherText, 26 - parseShift(key));
    }


    private String process(String text, int shift) {
        StringBuilder sb = new StringBuilder(text.length());
        for (char c : text.toCharArray())
            sb.append(Character.isLetter(c) ? shiftChar(c, shift) : c);
        return sb.toString();
    }


    private int parseShift(String key) throws Exception {
        try {
            int s = Integer.parseInt(key.trim());
            if (s < 0 || s > 25) throw new Exception("Shift must be 0–25.");
            return s;
        } catch (NumberFormatException e) {
            throw new Exception("Key must be a number (0–25).");
        }
    }

    @Override public String  getAlgorithmName() { return "Caesar Cipher"; }
    @Override public String  getKeyHint()        { return "Number 0–25  (e.g. 3)"; }
    @Override public boolean requiresKey()       { return true; }
}
