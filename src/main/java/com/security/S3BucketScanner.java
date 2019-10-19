package com.security;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.AccessControlList;
import com.amazonaws.services.s3.model.Bucket;
import com.amazonaws.services.s3.model.BucketPolicy;
import com.amazonaws.services.s3.model.Grant;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class S3BucketScanner {

    private static final Logger LOGGER = LoggerFactory.getLogger(S3BucketScanner.class);
    private Map<String, BucketState> bucketStateMap = null;

    // Constants
    public final String DEFAULT_STATE_FILE = "s3scanner.state";
    public final String DEFAULT_ROOT_DIR = System.getProperty("user.home");
    private final String ROOT_DIR_KEY = "root-dir";
    private final String STATE_FILE_KEY = "state-file";
    private final String ALL_USERS_GROUP = "http://acs.amazonaws.com/groups/global/AllUsers";
    private final String AUTHENTICATED_GROUP = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers";
    private final Set<String> PERMISSIONS = Collections.unmodifiableSet(
            new LinkedHashSet<>(Arrays.asList("READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL")));
    private final String BUCKET_ARN_PREFIX = "arn:aws:s3:::";
    private final Map<String, String> classificationMap = PermissionClassification.getMap();



    // Initializations
    private String ROOT_DIR = DEFAULT_ROOT_DIR;
    private String STATE_FILE = DEFAULT_STATE_FILE;



    public void configure(Map<String, String> propertiesMap){
        if(propertiesMap != null) {
            if(propertiesMap.containsKey(ROOT_DIR_KEY)){
                String rootDir = propertiesMap.get(ROOT_DIR_KEY).trim();
                if(!rootDir.equals("") && Files.exists(Paths.get(rootDir))) {
                    ROOT_DIR = rootDir;
                }
            }

            if(propertiesMap.containsKey(STATE_FILE_KEY)){
                String stateFile = propertiesMap.get(STATE_FILE_KEY);
                if(!stateFile.trim().equals("")) STATE_FILE = stateFile;
            }
        }

        loadState();
    }

    public JSONObject execute(){
        Map<String, List<String>> resultMap = new HashMap<>();
        scan(resultMap);
        serialize(bucketStateMap);
        return new JSONObject(resultMap);
    }

    public boolean loadState(){
        boolean stateFileExists = false;
        // Check if state already exists
        Path stateFilePath = Paths.get(ROOT_DIR, STATE_FILE);
        if(Files.exists(stateFilePath)){
            LOGGER.info("State file identified");
            try {
                Map<String, BucketState> map = null;
                FileInputStream fileInputStream = new FileInputStream(stateFilePath.toString());
                ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream);
                map = (HashMap) objectInputStream.readObject();
                bucketStateMap = map;
                stateFileExists = true;
                LOGGER.info("Using existing state...");
                objectInputStream.close();
            }catch (IOException ioException){
                LOGGER.error("Existing state file can't be opened");
            }catch (ClassNotFoundException cne){
                LOGGER.error("Error opening the state file");
            }
        }

        if(bucketStateMap == null){
            LOGGER.info("Building new state...");
            bucketStateMap = new HashMap<>();
        }

        return stateFileExists;
    }


    private void scan(Map<String, List<String>> resultMap){
        final AmazonS3 s3 = AmazonS3ClientBuilder.standard().withRegion(Regions.DEFAULT_REGION).build();
        List<Bucket> buckets = s3.listBuckets();
        for(Bucket bucket : buckets){
            try {
                List<Grant> grants = getAcls(s3, bucket.getName());
                BucketPolicy bucketPolicy = s3.getBucketPolicy(bucket.getName());
                BucketState curState = getBucketState(bucketPolicy, grants);
                if(bucketStateMap.containsKey(bucket.getName())){
                    if(curState.equals(bucketStateMap.get(bucket.getName())) && bucketStateMap.get(bucket.getName()).getAllowedAccess().size() > 0) {
                        resultMap.put(bucket.getName(), bucketStateMap.get(bucket.getName()).getAllowedAccess());
                        continue;
                    }
                } else {
                    bucketStateMap.put(bucket.getName(), curState);
                }

                checkAndUpdateBucketStatus(resultMap, bucket.getName(), grants, bucketPolicy);
                if(resultMap.containsKey(bucket.getName())){
                    bucketStateMap.get(bucket.getName()).setAllowedAccess(resultMap.get(bucket.getName()));
                }

            } catch (AmazonServiceException ase){
                   LOGGER.warn(ase.getErrorMessage());
            }
        }
        return;
    }

    public List<Grant> getAcls(AmazonS3 s3, String bucketName){
        AccessControlList acl = s3.getBucketAcl(bucketName);
        List<Grant> grants = acl.getGrantsAsList();
        return grants;
    }

    public void checkAndUpdateBucketStatus(Map<String, List<String>> resultMap, String bucketName,
                                                            List<Grant> grants, BucketPolicy bucketPolicy){


        Map<String, Integer> evaluationMap = evaluateBucketPolicy(bucketName, bucketPolicy);
        String[] permissionsArray = new String[PERMISSIONS.size()];
        PERMISSIONS.toArray(permissionsArray);

        if(grants != null && evaluationMap.get("FULL_CONTROL") != 3) {
            int permString = 2;
            for (Grant grant : grants) {
                String grantId = grant.getGrantee().getIdentifier();
                if(grantId.equals(ALL_USERS_GROUP) || grantId.equals(AUTHENTICATED_GROUP)){
                    if(evaluationMap.get(grant.getPermission().toString().trim()) < permString){
                        evaluationMap.put(grant.getPermission().toString().trim(), permString);
                    }
                }
            }

            boolean fullcontrol = true;
            List<String> allowedAccess = new ArrayList<>();
            for(int i = 0; i < permissionsArray.length-1; i++){
                if(evaluationMap.get(permissionsArray[i]) == 2) allowedAccess.add(permissionsArray[i]);
                else if(evaluationMap.get(permissionsArray[i]) == 3) fullcontrol = false;
            }

            if(fullcontrol && evaluationMap.get(permissionsArray[permissionsArray.length-1]) == 2){
                allowedAccess.add(permissionsArray[permissionsArray.length-1]);
            }

            if(allowedAccess.size() != 0)
                resultMap.put(bucketName, allowedAccess);
        }

    }


    // Evaluates the bucket policy with possible results: 1) True if the bucket is NOT open 2) False if the bucket is open
    public Map<String, Integer> evaluateBucketPolicy(String bucketName, BucketPolicy bucketPolicy){
        String bucketResource = BUCKET_ARN_PREFIX + bucketName + "/*";
        int permAssign = 1;
        Map<String, Integer> evaluationMap = new LinkedHashMap<>();
        for(String k : PERMISSIONS){
            evaluationMap.put(k, permAssign);
        }

        if(bucketPolicy.getPolicyText() == null) return evaluationMap;

        JSONObject jsonObject = new JSONObject(bucketPolicy.getPolicyText());
        JSONArray statement = jsonObject.getJSONArray("Statement");


        for(int i = 0; i < statement.length(); i++) {
            boolean allow = false;

            // Check for Principal
            JSONObject current = statement.getJSONObject(i);
            String principal = current.get("Principal").toString();
            if(!principal.equals("*") && !principal.equals("{\"AWS\":\"*\"}")){
                continue;
            }

            // Check for Resource
            if(current.get("Resource") instanceof  JSONArray) {
                JSONArray resourceArray = (JSONArray) current.get("Resource");
                Set<String> resouceSet = new TreeSet<>();
                for(int itr = 0; itr < resourceArray.length(); itr++){
                    resouceSet.add(resourceArray.getString(itr));
                }
                if(!resouceSet.contains(bucketResource)) continue;
            } else {
                if(!current.get("Resource").toString().contains(bucketResource)) continue;

            }

            // Check for condition
            if(current.has("Condition")){
                JSONObject condition = current.getJSONObject("Condition");
                boolean srcAddressPositive, srcAddressNegative;
                srcAddressNegative = condition.has("NotIpAddress") ? true : false;
                srcAddressPositive = condition.has("IpAddress") ? true : false;
                JSONObject IpAddressObject = srcAddressPositive ? condition.getJSONObject("IpAddress") : null;
                JSONObject NotIpAddressObject = srcAddressNegative ? condition.getJSONObject("NotIpAddress") : null;
                String srcIp = IpAddressObject != null && IpAddressObject.has("aws:SourceIp") ? IpAddressObject.getString("aws:SourceIp") : "";
                String notsrcIp = NotIpAddressObject != null && NotIpAddressObject.has("aws:SourceIp") ? NotIpAddressObject.getString("aws:SourceIp") : "";


                if(srcAddressPositive && !srcIp.equals("0.0.0.0/0")){
                    continue;
                } else if(srcAddressNegative && notsrcIp.equals("0.0.0.0/0")){
                    continue;
                }
            }

            // Check for effect
            if(current.get("Effect").equals("Allow")) {
                allow = true;
            }

            if( allow ) {
                permAssign = 2;
            } else {
                permAssign = 3;
            }

            // Check for Action
            JSONArray actionArray = null;
            if(current.get("Action") instanceof String){
                actionArray = new JSONArray();
                actionArray.put(current.getString("Action"));
            } else if(current.get("Action") instanceof  JSONArray) {
                actionArray = current.getJSONArray("Action");
            } else {
                throw new RuntimeException("Invalid type in 'Action' field of the bucket policy");
            }

            for(int itr = 0; itr < actionArray.length(); itr++){
                String actionPerm = actionArray.getString(itr).trim();
                if(!actionPerm.contains("s3:")) actionPerm = "s3:" + actionPerm;
                if(!classificationMap.containsKey(actionPerm)) {
                    throw new RuntimeException("Invalid permission in 'Action' field of the bucket policy");
                } else {
                    String action = classificationMap.get(actionPerm);
                    if(evaluationMap.get(action) < permAssign) evaluationMap.put(action, permAssign);
                }
            }



        }


        return evaluationMap;
    }

    private BucketState getBucketState(BucketPolicy bucketPolicy, List<Grant> grants){
        BucketState curState = null;
        if(bucketPolicy.getPolicyText() != null){
            curState = new BucketState(SHA1Hash.computeHash(grants.toString().getBytes()),
                    SHA1Hash.computeHash(bucketPolicy.getPolicyText().getBytes()));
        } else {
            curState = new BucketState(SHA1Hash.computeHash(grants.toString().getBytes()));
        }

        return curState;
    }


    private void serialize(Map<String, BucketState> bucketStateMap){

        try {
            Path stateFilePath = Paths.get(ROOT_DIR, STATE_FILE);
            FileOutputStream fos = new FileOutputStream(stateFilePath.toString());
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(bucketStateMap);
            oos.close();
        } catch (IOException ioe) {
            LOGGER.info("State can't be saved");
            LOGGER.error(ioe.getMessage());
            throw new RuntimeException(ioe);
        }
    }

}
