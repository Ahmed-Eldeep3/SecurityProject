package com.example.security.factory;


import com.example.security.algorithms.AesCipher;
import com.example.security.algorithms.AutokeyCipher;
import com.example.security.algorithms.CaesarCipher;
import com.example.security.algorithms.DesCipher;
import com.example.security.algorithms.MonoalphabeticCipher;
import com.example.security.algorithms.PlayfairCipher;
import com.example.security.algorithms.PolyalphabeticCipher;
import com.example.security.algorithms.RailFenceCipher;
import com.example.security.algorithms.RsaCipher;
import com.example.security.base.AlgorithmType;
import com.example.security.base.CipherAlgorithm;

public final class CipherFactory {

    private CipherFactory() { }

    public static CipherAlgorithm create(AlgorithmType type) {
        switch (type) {
            case CAESAR:          return new CaesarCipher();
            case MONOALPHABETIC:  return new MonoalphabeticCipher();
            case PLAYFAIR:        return new PlayfairCipher();
            case POLYALPHABETIC:  return new PolyalphabeticCipher();
            case AUTOKEY:         return new AutokeyCipher();
            case RAIL_FENCE:      return new RailFenceCipher();
            case DES:             return new DesCipher();
            case RSA:             return new RsaCipher();
            case AES:             return new AesCipher();
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + type);
        }
    }
}