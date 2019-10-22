package com.security;

import static org.junit.Assert.assertTrue;

import com.amazonaws.services.s3.model.BucketPolicy;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit test for simple ScannerMain.
 */
public class S3BucketScannerTest
{
    private final String ROOT_DIR_KEY = "root-dir";
    private final String STATE_FILE_KEY = "state-file";
    private Map<String, String> propertiesMap = null;
    private S3BucketScanner s3BucketScanner;

    @Before
    public void Setup(){
        propertiesMap = new HashMap<>();
        propertiesMap.put(ROOT_DIR_KEY,
                Paths.get(this.getClass().getClassLoader().getResource("s3scanner-test.properties").getPath()).getParent().toString());
        propertiesMap.put(STATE_FILE_KEY, "s3scanner-test");
        s3BucketScanner = new S3BucketScanner();
        s3BucketScanner.configure(propertiesMap);
    }


    @Test
    public void TestLoadState()
    {
        Assert.assertEquals(false, s3BucketScanner.loadState());
    }

    @Test
    public void TestBucketPolicyEvaluation1(){
        evaluateBucketPolicy(new int[]{2,1,1,1,1}, BucketPolicySamples.BucketPolicy1,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation2(){
        evaluateBucketPolicy(new int[]{2,1,1,1,1}, BucketPolicySamples.BucketPolicy2,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation3(){
        evaluateBucketPolicy(new int[]{1,1,1,1,1}, BucketPolicySamples.BucketPolicy3,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation4(){
        evaluateBucketPolicy(new int[]{1,1,1,1,1}, BucketPolicySamples.BucketPolicy4,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation5(){
        evaluateBucketPolicy(new int[]{1,1,1,1,2}, BucketPolicySamples.BucketPolicy5,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation6(){
        evaluateBucketPolicy(new int[]{1,1,1,1,1}, BucketPolicySamples.BucketPolicy6,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation7(){
        evaluateBucketPolicy(new int[]{1,1,1,1,2}, BucketPolicySamples.BucketPolicy7,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation8(){
        evaluateBucketPolicy(new int[]{2,1,1,1,1}, BucketPolicySamples.BucketPolicy8,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation9(){
        evaluateBucketPolicy(new int[]{2,1,1,1,1}, BucketPolicySamples.BucketPolicy9,  "examplebucket");
    }

    @Test
    public void TestBucketPolicyEvaluation10(){
        evaluateBucketPolicy(new int[]{1,1,1,1,1}, BucketPolicySamples.BucketPolicy10,  "examplebucket");
    }


    private void evaluateBucketPolicy(int[] expected, String policyString, String bucketName){
        BucketPolicy bucketPolicy = new BucketPolicy();
        bucketPolicy.setPolicyText(policyString);
        Map<String, Integer> evaluationMap = s3BucketScanner.evaluateBucketPolicy(bucketName, bucketPolicy);
        checkEvaluationResult(expected, evaluationMap);
    }

    private void checkEvaluationResult(int[] perms, Map<String, Integer> evaluationMap){
        Assert.assertEquals(perms[0], evaluationMap.get("READ").intValue());
        Assert.assertEquals(perms[1], evaluationMap.get("WRITE").intValue());
        Assert.assertEquals(perms[2], evaluationMap.get("READ_ACP").intValue());
        Assert.assertEquals(perms[3], evaluationMap.get("WRITE_ACP").intValue());
        Assert.assertEquals(perms[4], evaluationMap.get("FULL_CONTROL").intValue());
    }
}
