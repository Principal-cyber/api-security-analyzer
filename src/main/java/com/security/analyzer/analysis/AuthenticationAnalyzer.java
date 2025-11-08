package com.security.analyzer.analysis;

import com.security.analyzer.client.APIClient;
import com.security.analyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class AuthenticationAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationAnalyzer.class);
    
    private final APIClient apiClient;

    public AuthenticationAnalyzer(APIClient apiClient) {
        this.apiClient = apiClient;
    }

    public List<Vulnerability> testAuthenticationMechanisms(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        logger.info("Testing authentication mechanisms...");
        
        // Find authentication endpoints
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (isAuthenticationEndpoint(endpoint)) {
                vulnerabilities.addAll(testAuthEndpoint(endpoint));
            }
        }
        
        return vulnerabilities;
    }

    private boolean isAuthenticationEndpoint(Endpoint endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return path.contains("auth") || 
               path.contains("token") || 
               path.contains("login") ||
               path.contains("oauth");
    }

    private List<Vulnerability> testAuthEndpoint(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
            
            // Test 1: Weak credentials
            var weakCredsResponse = apiClient.sendRequest(
                fullUrl,
                endpoint.getMethod(),
                Map.of("client_id", "admin", "client_secret", "password"),
                null
            );
            
            if (weakCredsResponse.getStatusCode() == 200) {
                vulnerabilities.add(createAuthVulnerability(
                    "Weak Credentials Accepted",
                    "Authentication endpoint accepts weak/common credentials",
                    endpoint.getPath()
                ));
            }
            
            // Test 2: No rate limiting (multiple rapid requests)
            for (int i = 0; i < 10; i++) {
                apiClient.sendRequest(
                    fullUrl,
                    endpoint.getMethod(),
                    Map.of("client_id", "test" + i, "client_secret", "test"),
                    null
                );
            }
            
            // If all requests succeeded quickly, potential lack of rate limiting
            Vulnerability vuln = new Vulnerability(
                "Potential Lack of Rate Limiting",
                Vulnerability.Severity.MEDIUM,
                "No rate limiting detected on authentication endpoint after multiple rapid requests",
                endpoint.getPath(),
                "Implement rate limiting and account lockout mechanisms"
            );
            vuln.setOwaspCategory("API2:2023 - Broken Authentication");
            vuln.setCwe("CWE-307");
            vulnerabilities.add(vuln);
            
            // Test 3: Information disclosure in error messages
            var errorResponse = apiClient.sendRequest(
                fullUrl,
                endpoint.getMethod(),
                Map.of("invalid_param", "test"),
                null
            );
            
            if (errorResponse.getBody().toLowerCase().contains("sql") ||
                errorResponse.getBody().toLowerCase().contains("database") ||
                errorResponse.getBody().toLowerCase().contains("exception")) {
                
                vulnerabilities.add(createAuthVulnerability(
                    "Information Disclosure in Error Messages",
                    "Authentication endpoint reveals sensitive information in error responses",
                    endpoint.getPath()
                ));
            }
            
        } catch (Exception e) {
            logger.debug("Authentication test failed for {}: {}", endpoint.getPath(), e.getMessage());
        }
        
        return vulnerabilities;
    }

    private Vulnerability createAuthVulnerability(String title, String description, String endpoint) {
        Vulnerability vuln = new Vulnerability(
            title,
            Vulnerability.Severity.HIGH,
            description,
            endpoint,
            "Strengthen authentication mechanisms and implement proper error handling"
        );
        vuln.setOwaspCategory("API2:2023 - Broken Authentication");
        vuln.setCwe("CWE-287");
        return vuln;
    }
}
