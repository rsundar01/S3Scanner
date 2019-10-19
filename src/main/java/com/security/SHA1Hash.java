package com.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA1Hash {

    private static final String HASH_ALGORITHM = "SHA-1";

    public static byte[] computeHash(byte[] iData){
        byte[] computedHash = null;
        try{
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            md.update(iData);
            computedHash = md.digest();
        }catch(NoSuchAlgorithmException nsaException){
            throw new RuntimeException(nsaException.getMessage());
        }
        return computedHash;
    }


}
