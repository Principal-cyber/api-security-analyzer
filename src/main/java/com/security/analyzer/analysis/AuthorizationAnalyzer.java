package com.security.analyzer.analysis;

import com.security.analyzer.client.APIClient;
import com.security.analyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthorizationAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationAnalyzer.class);
    
    private final APIClient apiClient;

    public AuthorizationAnalyzer(APIClient apiClient) {
        this.apiClient = apiClient;
    }

    public List<Vulnerability> testAuthorization(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        logger.info("Testing authorization mechanisms...");
        
        // Test endpoints that should require authentication
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (requiresAuthentication(endpoint)) {
                vulnerabilities.addAll(testEndpointAuthorization(endpoint));
            }
        }
        
        return vulnerabilities;
    }

    private boolean requiresAuthentication(Endpoint endpoint) {
        // Check if endpoint has security requirements
        return endpoint.getSecurity() != null && !endpoint.getSecurity().isEmpty();
    }

    private List<Vulnerability> testEndpointAuthorization(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
            
            // Test without authentication
            var response = apiClient.sendRequest(fullUrl, endpoint.getMethod(), null, null);
            
            if (response.getStatusCode() == 200) {
                Vulnerability vuln = new Vulnerability(
                    "Missing Authentication",
                    Vulnerability.Severity.HIGH,
                    "Endpoint accessible without proper authentication",
                    endpoint.getPath(),
                    "Implement proper authentication checks for all sensitive endpoints"
                );
                vuln.setOwaspCategory("API2:2023 - Broken Authentication");
                vuln.setCwe("CWE-306");
                vulnerabilities.add(vuln);
            } else if (response.getStatusCode() == 401 || response.getStatusCode() == 403) {
                logger.info("Endpoint {} properly requires authentication", endpoint.getPath());
            }
            
        } catch (Exception e) {
            logger.debug("Authorization test failed for {}: {}", endpoint.getPath(), e.getMessage());
        }
        
        return vulnerabilities;
    }
}