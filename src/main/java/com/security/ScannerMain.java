package com.security;


import java.io.IOException;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ScannerMain
{
    private static final Logger LOGGER = LoggerFactory.getLogger(ScannerMain.class);

    public static void main( String[] args )
    {
        S3BucketScanner s3BucketScanner = new S3BucketScanner();
        s3BucketScanner.configure(null);
        System.out.println(s3BucketScanner.execute());

    }
}
