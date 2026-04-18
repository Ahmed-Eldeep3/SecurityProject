package com.example.security.algorithms;


public class RailFenceCipher extends BaseCipher {

    @Override
    public String encrypt(String plainText, String key) throws Exception {
        int rails = parseRails(key, plainText.length());
        StringBuilder[] fence = new StringBuilder[rails];
        for (int i = 0; i < rails; i++) fence[i] = new StringBuilder();

        int r = 0; boolean down = true;
        for (char c : plainText.toCharArray()) {
            fence[r].append(c);
            if      (r == rails - 1) down = false;
            else if (r == 0)         down = true;
            r += down ? 1 : -1;
        }

        StringBuilder result = new StringBuilder();
        for (StringBuilder row : fence) result.append(row);
        return result.toString();
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        int rails   = parseRails(key, cipherText.length());
        int len     = cipherText.length();
        int[] pattern = buildZigzag(len, rails);

        int[] lengths = new int[rails];
        for (int rIdx : pattern) lengths[rIdx]++;

        char[][] fence  = new char[rails][];
        int pos = 0;
        for (int i = 0; i < rails; i++) {
            fence[i] = new char[lengths[i]];
            for (int j = 0; j < lengths[i]; j++)
                fence[i][j] = cipherText.charAt(pos++);
        }

        int[] idx = new int[rails];
        StringBuilder result = new StringBuilder(len);
        for (int rIdx : pattern) result.append(fence[rIdx][idx[rIdx]++]);
        return result.toString();
    }


    private int[] buildZigzag(int len, int rails) {
        int[] pattern = new int[len];
        int r = 0; boolean down = true;
        for (int i = 0; i < len; i++) {
            pattern[i] = r;
            if      (r == rails - 1) down = false;
            else if (r == 0)         down = true;
            r += down ? 1 : -1;
        }
        return pattern;
    }

    private int parseRails(String key, int textLen) throws Exception {
        try {
            int rails = Integer.parseInt(key.trim());
            if (rails < 2)       throw new Exception("Rails must be ≥ 2.");
            if (rails >= textLen) throw new Exception("Rails must be less than text length.");
            return rails;
        } catch (NumberFormatException e) {
            throw new Exception("Key must be a number ≥ 2.");
        }
    }

    @Override public String  getAlgorithmName() { return "Rail Fence Cipher"; }
    @Override public String  getKeyHint()        { return "Number of rails ≥ 2  (e.g. 3)"; }
    @Override public boolean requiresKey()       { return true; }
}
