package com.example.security.algorithms;


public class PolyalphabeticCipher extends BaseCipher {

    @Override
    public String encrypt(String plainText, String key) throws Exception {
        return process(plainText, normalizeLettersKey(key), true);
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        return process(cipherText, normalizeLettersKey(key), false);
    }

    private String process(String text, String key, boolean encrypt) {
        StringBuilder sb = new StringBuilder(text.length());
        int keyIdx = 0;

        for (char c : text.toCharArray()) {
            if (!Character.isLetter(c)) { sb.append(c); continue; }

            int shift  = charIndex(key.charAt(keyIdx % key.length()));
            int offset = encrypt ? shift : (26 - shift);
            sb.append(shiftChar(c, offset));
            keyIdx++;
        }
        return sb.toString();
    }

    @Override public String  getAlgorithmName() { return "Polyalphabetic (Vigenère) Cipher"; }
    @Override public String  getKeyHint()        { return "Keyword  (e.g. KEY)"; }
    @Override public boolean requiresKey()       { return true; }
}
