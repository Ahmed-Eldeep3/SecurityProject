package com.example.security.algorithms;


public class AutokeyCipher extends BaseCipher {

    @Override
    public String encrypt(String plainText, String key) throws Exception {
        String k = normalizeLettersKey(key);

        StringBuilder keystream = new StringBuilder(k);
        for (char c : plainText.toCharArray())
            if (Character.isLetter(c)) keystream.append(Character.toLowerCase(c));

        return applyKeystream(plainText, keystream.toString(), true);
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        String k = normalizeLettersKey(key);

        StringBuilder keystream = new StringBuilder(k);
        StringBuilder result    = new StringBuilder();
        int ki = 0;

        for (char c : cipherText.toCharArray()) {
            if (!Character.isLetter(c)) { result.append(c); continue; }

            int  shift     = charIndex(keystream.charAt(ki++));
            char decrypted = shiftChar(c, 26 - shift);
            result.append(decrypted);

            keystream.append(Character.toLowerCase(decrypted));
        }
        return result.toString();
    }

    // ── Core ──────────────────────────────────────────────────────

    private String applyKeystream(String text, String keystream, boolean encrypt) {
        StringBuilder sb = new StringBuilder(text.length());
        int ki = 0;
        for (char c : text.toCharArray()) {
            if (!Character.isLetter(c)) { sb.append(c); continue; }
            int shift  = charIndex(keystream.charAt(ki++));
            int offset = encrypt ? shift : (26 - shift);
            sb.append(shiftChar(c, offset));
        }
        return sb.toString();
    }

    @Override public String  getAlgorithmName() { return "Autokey Cipher"; }
    @Override public String  getKeyHint()        { return "Keyword  (e.g. KEY)"; }
    @Override public boolean requiresKey()       { return true; }
}
