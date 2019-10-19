# S3Scanner


Build:
#> mvn clean package

Execute:
#> java -jar s3-scanner-1.0-SNAPSHOT.jar 


Features:

* Tool evaluates the bucket access with the following logic: Implicit Deny < Explicit Allow < Explicit Deny
* Bucket policies are evaluated first, ACLs are evaluated second. Union of the evaluation is provided as result
* The states of each bucket is stored in a file in the home directory ~/.s3scanner/scanner.state
* During every invocation the tool reads the state and updates it if there are changes
* Output is a Json string with bucketname as key and value is a JsonArray with the list of access [Possible values: READ, WRITE,
READ_ACP, WRITE_ACP, FULL_CONTROL]


Limitation:
* Tool uses credentials in the default credentials location ~/.aws/credentials, uses only the default profile and region
associated with it. No other options exists
* Evaluation of the bucket policy is not thorough and complete. There is a lot of opportunites for false positives



Bugs:
* Output has amazon java sdk warning which can be ignored
* There is a bug in bucket policy evaluation. The tool will look for explicit deny rules and overrules any explicit allow rules.
But since the permissions in policy is fine grained, even if one of the permission in the category is in the 'deny' policy
the tool will apply the rule for the entire category. For example, deny on get-object will be translated to deny on READ. This
is a bug
* Intended location of the state file is ~/.s3scanner/ but the tool now writes it to ~/
