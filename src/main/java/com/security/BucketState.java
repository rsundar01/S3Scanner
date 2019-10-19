package com.security;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class BucketState implements Serializable {

    private byte[] hashGrant = new byte[20];
    private byte[] hashPolicy = new byte[20];
    private List<String> allowedAccess = new ArrayList<>();

    public BucketState(byte[] hashGrant){
        if(hashGrant != null) {
            System.arraycopy(this.hashGrant, 0, hashGrant, 0,
                    (hashGrant.length < this.hashGrant.length) ? hashGrant.length
                            : this.hashGrant.length);
        }
    }

    public BucketState(byte[] hashGrant, byte[] hashPolicy){
        this(hashGrant);

        if(hashPolicy != null) {
            System.arraycopy(this.hashPolicy, 0, hashPolicy, 0,
                    hashPolicy.length < this.hashPolicy.length ? hashPolicy.length
                            : this.hashPolicy.length);
        }
    }

    public List<String> getAllowedAccess(){
        return allowedAccess;
    }

    public void setAllowedAccess(List<String> allowedAccess){
        if(allowedAccess != null){
            this.allowedAccess = allowedAccess;
        }
    }

    @Override
    public boolean equals(Object o) {
        if(this == o) return true;
        if(o == null || o.getClass() != this.getClass()) return false;
        BucketState bo = (BucketState) o;
        if(!compareByteArray(hashGrant, bo.hashGrant)) return false;
        return compareByteArray(hashPolicy, bo.hashPolicy);
    }

    private boolean compareByteArray(byte[] a, byte[] b){
        if(a == null || b == null) return false;
        if(a.length != b.length) return false;
        for(int i = 0;i < a.length; i++){
            if(a[i] != b[i]) return false;
        }
        return true;
    }


}
