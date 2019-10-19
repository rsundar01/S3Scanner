package com.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PropertiesProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(PropertiesProvider.class);

    private static final String PROPERTY_FILE_NAME = "s3scanner.properties";
    private static Map<String, String> propertiesMap = null;
    private static final String[] MANDATORY_PROPERTIES = {"credentials-file", "root-dir"};

    private PropertiesProvider(){}

    public static Map<String, String> getProperties() throws IOException{

        if(propertiesMap == null) {
            synchronized (PropertiesProvider.class) {
                if (propertiesMap == null) {
                    Properties properties = new Properties();
                    properties.load(PropertiesProvider.class.getClassLoader()
                            .getResource(PROPERTY_FILE_NAME).openStream());
                    propertiesMap = new HashMap((Map)properties);
                    validateProperties(propertiesMap);
                    checkAndCreateRootDir(propertiesMap.get(MANDATORY_PROPERTIES[1]));
                }
            }
        }

        return propertiesMap;
    }

    private static void validateProperties(Map<String, String> propertiesMap) {
        for(int i = 0; i < MANDATORY_PROPERTIES.length; i++){
            if(!propertiesMap.containsKey(MANDATORY_PROPERTIES[i])){
                String msg = String.format("Insufficient configuration: Missing configuration '%s'",
                        MANDATORY_PROPERTIES[i]);
                LOGGER.error(msg);
                throw new RuntimeException(msg);
            }
        }
    }

    private static void checkAndCreateRootDir(String rootDir) throws IOException {
        if(Files.exists(Paths.get(rootDir))){
            LOGGER.info("Root directory {} already exists", rootDir);
        } else {
            LOGGER.info("Root directory {} not found. Creating directory...", rootDir);
            Files.createDirectory(Paths.get(rootDir));
            if(!Files.exists(Paths.get(rootDir))){
                String msg = String.format("Error creating root directory %s", rootDir);
                LOGGER.error(msg);
                throw new RuntimeException(msg);
            } else {
                LOGGER.info("Root directory successfully created {}", rootDir);
            }

        }
    }

}
