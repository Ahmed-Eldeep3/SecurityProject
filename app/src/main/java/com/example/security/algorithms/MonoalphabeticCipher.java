package com.example.security.algorithms;


public class MonoalphabeticCipher extends BaseCipher {

    @Override
    public String encrypt(String plainText, String key) throws Exception {
        String k = validateKey(key);
        return substitute(plainText, k, false);
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        String k = validateKey(key);
        return substitute(cipherText, k, true);
    }


    private String substitute(String text, String key, boolean inverse) {
        StringBuilder sb = new StringBuilder(text.length());
        for (char c : text.toCharArray()) {
            if (!Character.isLetter(c)) { sb.append(c); continue; }

            boolean upper = Character.isUpperCase(c);
            char lower    = Character.toLowerCase(c);
            char result;

            if (!inverse) {

                result = key.charAt(lower - 'a');
            } else {

                result = (char) ('a' + key.indexOf(lower));
            }
            sb.append(upper ? Character.toUpperCase(result) : result);
        }
        return sb.toString();
    }


    private String validateKey(String key) throws Exception {
        String k = key.trim().toLowerCase();
        if (k.length() != 26)
            throw new Exception("Key must be exactly 26 letters. Got: " + k.length());

        boolean[] seen = new boolean[26];
        for (char c : k.toCharArray()) {
            if (!Character.isLetter(c))
                throw new Exception("Key must contain letters only.");
            if (seen[c - 'a'])
                throw new Exception("Duplicate letter '" + c + "'. All 26 must be unique.");
            seen[c - 'a'] = true;
        }
        return k;
    }

    @Override public String  getAlgorithmName() { return "Monoalphabetic Cipher"; }
    @Override public String  getKeyHint()        { return "26 unique letters  (e.g. QWERTYUIOPASDFGHJKLZXCVBNM)"; }
    @Override public boolean requiresKey()       { return true; }
}
