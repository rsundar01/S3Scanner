package com.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class PermissionClassification {


    public static Map<String, String> getMap(){

        Map<String, String> lookup = new HashMap<>();

        lookup.put("s3:ListBucket", "READ");
        lookup.put("s3:ListBucketVersions", "READ");
        lookup.put("s3:ListBucketMultipartUploads", "READ");
        lookup.put("s3:GetObject", "READ");
        lookup.put("s3:GetObjectVersion", "READ");
        lookup.put("s3:GetObjectTorrent", "READ");
        lookup.put("s3:PutObject", "WRITE");
        lookup.put("s3:DeleteObject", "WRITE");
        lookup.put("s3:GetBucketAcl", "READ_ACP");
        lookup.put("s3:GetObjectAcl", "READ_ACP");
        lookup.put("s3:GetObjectVersionAcl", "READ_ACP");
        lookup.put("s3:PutBucketAcl", "WRITE_ACP");
        lookup.put("s3:PutObjectAcl", "WRITE_ACP");
        lookup.put("s3:PutObjectVersionAcl", "WRITE_ACP");
        lookup.put("s3:*", "FULL_CONTROL");

        return Collections.unmodifiableMap(lookup);
    }

}
