package com.example.security.algorithms;


public class PlayfairCipher extends BaseCipher {

    @Override
    public String encrypt(String plainText, String key) throws Exception {
        char[][] matrix = buildMatrix(key);
        String prepared = prepareText(plainText);
        return processDigraphs(prepared, matrix, true);
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        char[][] matrix = buildMatrix(key);
        String upper    = normalize(cipherText);
        if (upper.length() % 2 != 0)
            throw new Exception("Ciphertext length must be even.");
        return processDigraphs(upper, matrix, false);
    }


    private char[][] buildMatrix(String keyword) {
        String cleaned = normalize(keyword);
        StringBuilder ks = new StringBuilder();

        for (char c : cleaned.toCharArray())
            if (ks.indexOf(String.valueOf(c)) < 0) ks.append(c);

        for (char c = 'A'; c <= 'Z'; c++) {
            if (c == 'J') continue;
            if (ks.indexOf(String.valueOf(c)) < 0) ks.append(c);
        }

        char[][] m = new char[5][5];
        for (int i = 0; i < 25; i++) m[i/5][i%5] = ks.charAt(i);
        return m;
    }

    private int[] pos(char[][] m, char c) {
        if (c == 'J') c = 'I';
        for (int r = 0; r < 5; r++)
            for (int cl = 0; cl < 5; cl++)
                if (m[r][cl] == c) return new int[]{r, cl};
        return new int[]{-1, -1};
    }


    private String prepareText(String text) {
        String up = normalize(text);
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < up.length()) {
            char first = up.charAt(i++);
            sb.append(first);
            if (i < up.length()) {
                char second = up.charAt(i);
                if (first == second) { sb.append('X'); }
                else                 { sb.append(second); i++; }
            }
        }
        if (sb.length() % 2 != 0) sb.append('X');
        return sb.toString();
    }


    private String processDigraphs(String text, char[][] m, boolean enc) {
        int step = enc ? 1 : -1;
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < text.length(); i += 2) {
            int[] a = pos(m, text.charAt(i));
            int[] b = pos(m, text.charAt(i + 1));

            if (a[0] == b[0]) {                              // Same row
                sb.append(m[a[0]][(a[1]+step+5)%5]);
                sb.append(m[b[0]][(b[1]+step+5)%5]);
            } else if (a[1] == b[1]) {                       // Same col
                sb.append(m[(a[0]+step+5)%5][a[1]]);
                sb.append(m[(b[0]+step+5)%5][b[1]]);
            } else {                                         // Rectangle
                sb.append(m[a[0]][b[1]]);
                sb.append(m[b[0]][a[1]]);
            }
        }
        return sb.toString();
    }


    private String normalize(String s) {
        return s.toUpperCase().replaceAll("[^A-Z]", "").replace('J', 'I');
    }

    @Override public String  getAlgorithmName() { return "Playfair Cipher"; }
    @Override public String  getKeyHint()        { return "Keyword (letters only)  e.g. MONARCHY"; }
    @Override public boolean requiresKey()       { return true; }
}
