package com.example.security.base;

public enum AlgorithmType {

    CAESAR       ("Caesar Cipher",          "Shift value (0–25)",           true),
    MONOALPHABETIC("Monoalphabetic Cipher", "26-char substitution key",     true),
    PLAYFAIR     ("Playfair Cipher",         "Keyword (letters only)",       true),
    POLYALPHABETIC("Polyalphabetic (Vigenère)", "Keyword (letters only)",   true),
    AUTOKEY      ("Autokey Cipher",          "Keyword (letters only)",       true),
    RAIL_FENCE   ("Rail Fence Cipher",       "Number of rails (≥ 2)",       true),
    DES          ("DES",                     "8-character key (64-bit)",     true),
    RSA          ("RSA",                     "Key size in bits (512/1024)",  true),
    AES          ("AES",                     "16, 24, or 32-character key",  true);

    private final String displayName;
    private final String keyHint;
    private final boolean requiresKey;

    AlgorithmType(String displayName, String keyHint, boolean requiresKey) {
        this.displayName  = displayName;
        this.keyHint      = keyHint;
        this.requiresKey  = requiresKey;
    }

    public String  getDisplayName() { return displayName; }
    public String  getKeyHint()     { return keyHint;     }
    public boolean isRequiresKey()  { return requiresKey; }
}
