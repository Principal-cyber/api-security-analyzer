package com.security.analyzer.plugins.fuzzing;

import com.security.analyzer.client.APIClient;
import com.security.analyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class FuzzingEngine {
    private static final Logger logger = LoggerFactory.getLogger(FuzzingEngine.class);
    
    private final APIClient apiClient;
    private final PayloadGenerator payloadGenerator;

    public FuzzingEngine(APIClient apiClient) {
        this.apiClient = apiClient;
        this.payloadGenerator = new PayloadGenerator();
    }

    public List<Vulnerability> runFuzzingTests(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        logger.info("Running fuzzing tests...");
        
        // Test a few key endpoints with fuzzing
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (endpoint.getMethod().equalsIgnoreCase("POST") || 
                endpoint.getMethod().equalsIgnoreCase("GET")) {
                
                vulnerabilities.addAll(fuzzEndpoint(endpoint));
                break; // Just test one endpoint for demo
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> fuzzEndpoint(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        List<String> fuzzPayloads = payloadGenerator.generateFuzzPayloads();
        
        for (String payload : fuzzPayloads) {
            try {
                String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
                long startTime = System.currentTimeMillis();
                
                var response = apiClient.sendRequest(
                    fullUrl,
                    endpoint.getMethod(),
                    Map.of("input", payload, "data", payload, "param", payload),
                    null
                );
                
                long responseTime = System.currentTimeMillis() - startTime;
                
                // Analyze response for anomalies
                if (isAnomalousResponse(response, responseTime)) {
                    Vulnerability vuln = new Vulnerability(
                        "Fuzzing - Anomalous Response",
                        Vulnerability.Severity.MEDIUM,
                        "Unusual response to fuzzing payload: " + payload,
                        endpoint.getPath(),
                        "Improve input validation and error handling"
                    );
                    vuln.setPayload(payload);
                    vuln.setHttpStatus(response.getStatusCode());
                    vuln.setResponseTime(responseTime);
                    vuln.setOwaspCategory("API8:2023 - Security Misconfiguration");
                    vulnerabilities.add(vuln);
                }
                
            } catch (Exception e) {
                logger.debug("Fuzzing test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }
        
        return vulnerabilities;
    }

    private boolean isAnomalousResponse(APIClient.HttpResponse response, long responseTime) {
        return response.getStatusCode() == 500 || // Server errors
               responseTime > 5000 || // Very slow responses
               response.getBody().contains("exception") || // Exceptions in response
               response.getBody().contains("error") || // Error messages
               response.getBody().contains("stack trace") || // Stack traces
               response.getBody().length() > 10000; // Very large responses
    }
}
