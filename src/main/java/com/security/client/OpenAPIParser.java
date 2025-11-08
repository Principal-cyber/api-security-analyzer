package com.security.analyzer.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.analyzer.model.APISpecification;
import com.security.analyzer.model.Endpoint;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OpenAPIParser {
    private static final Logger logger = LoggerFactory.getLogger(OpenAPIParser.class);
    private final ObjectMapper objectMapper;
    private final OkHttpClient httpClient;

    public OpenAPIParser() {
        this.objectMapper = new ObjectMapper();
        this.httpClient = new OkHttpClient();
    }

    public APISpecification parseFromUrl(String openApiUrl) {
        try {
            logger.info("Fetching OpenAPI specification from: {}", openApiUrl);
            
            Request request = new Request.Builder()
                .url(openApiUrl)
                .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    throw new RuntimeException("Failed to fetch OpenAPI spec: " + response.code());
                }

                String json = response.body().string();
                return parseFromJson(json);
            }
            
        } catch (Exception e) {
            logger.error("Error parsing OpenAPI specification: {}", e.getMessage());
            throw new RuntimeException("Failed to parse OpenAPI specification", e);
        }
    }

    public APISpecification parseFromJson(String jsonContent) {
        try {
            APISpecification spec = objectMapper.readValue(jsonContent, APISpecification.class);
            extractEndpoints(spec);
            return spec;
            
        } catch (Exception e) {
            logger.error("Error parsing JSON content: {}", e.getMessage());
            throw new RuntimeException("Failed to parse JSON content", e);
        }
    }

    private void extractEndpoints(APISpecification spec) {
        List<Endpoint> endpoints = new ArrayList<>();
        
        if (spec.getPaths() != null) {
            for (Map.Entry<String, Map<String, Object>> pathEntry : spec.getPaths().entrySet()) {
                String path = pathEntry.getKey();
                Map<String, Object> methods = pathEntry.getValue();
                
                for (Map.Entry<String, Object> methodEntry : methods.entrySet()) {
                    String method = methodEntry.getKey().toUpperCase();
                    
                    if (isHttpMethod(method)) {
                        Endpoint endpoint = new Endpoint(path, method);
                        
                        // Extract endpoint details
                        Map<String, Object> endpointDetails = (Map<String, Object>) methodEntry.getValue();
                        if (endpointDetails != null) {
                            endpoint.setOperationId((String) endpointDetails.get("operationId"));
                            endpoint.setParameters((List<Endpoint.Parameter>) endpointDetails.get("parameters"));
                            endpoint.setSecurity((List<Map<String, Object>>) endpointDetails.get("security"));
                            endpoint.setRequestBody((Map<String, Object>) endpointDetails.get("requestBody"));
                        }
                        
                        endpoints.add(endpoint);
                    }
                }
            }
        }
        
        spec.setEndpoints(endpoints);
    }

    private boolean isHttpMethod(String method) {
        return method.equalsIgnoreCase("GET") ||
               method.equalsIgnoreCase("POST") ||
               method.equalsIgnoreCase("PUT") ||
               method.equalsIgnoreCase("DELETE") ||
               method.equalsIgnoreCase("PATCH") ||
               method.equalsIgnoreCase("HEAD") ||
               method.equalsIgnoreCase("OPTIONS");
    }
}