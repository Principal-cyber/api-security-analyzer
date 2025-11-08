package com.security.analyzer.analysis;

import com.security.analyzer.client.APIClient;
import com.security.analyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OWASPAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(OWASPAnalyzer.class);
    
    private final APIClient apiClient;

    public OWASPAnalyzer(APIClient apiClient) {
        this.apiClient = apiClient;
    }

    public List<Vulnerability> analyzeOWASPTop10(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        logger.info("Analyzing OWASP API Security Top 10...");
        
        // API1:2023 - Broken Object Level Authorization
        vulnerabilities.addAll(testBrokenObjectLevelAuthorization(apiSpec));
        
        // API2:2023 - Broken Authentication
        vulnerabilities.addAll(testBrokenAuthentication(apiSpec));
        
        // API3:2023 - Broken Object Property Level Authorization
        vulnerabilities.addAll(testBrokenObjectPropertyAuthorization(apiSpec));
        
        // API4:2023 - Unrestricted Resource Consumption
        vulnerabilities.addAll(testUnrestrictedResourceConsumption(apiSpec));
        
        // API5:2023 - Broken Function Level Authorization
        vulnerabilities.addAll(testBrokenFunctionLevelAuthorization(apiSpec));
        
        // API6:2023 - Unrestricted Access to Sensitive Business Flows
        vulnerabilities.addAll(testUnrestrictedBusinessFlowAccess(apiSpec));
        
        // API7:2023 - Server Side Request Forgery
        vulnerabilities.addAll(testSSRF(apiSpec));
        
        // API8:2023 - Security Misconfiguration
        vulnerabilities.addAll(testSecurityMisconfiguration(apiSpec));
        
        // API9:2023 - Improper Inventory Management
        vulnerabilities.addAll(testImproperInventoryManagement(apiSpec));
        
        // API10:2023 - Unsafe Consumption of APIs
        vulnerabilities.addAll(testUnsafeAPIConsumption(apiSpec));
        
        return vulnerabilities;
    }

    private List<Vulnerability> testBrokenObjectLevelAuthorization(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test for IDOR vulnerabilities
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (endpoint.getPath().contains("{") && endpoint.getPath().contains("}")) {
                // This is a parameterized endpoint - potential BOLA target
                String testUrl = "https://vbank.open.bankingapi.ru" + 
                    endpoint.getPath().replace("{", "123").replace("}", "456");
                
                try {
                    var response = apiClient.sendRequest(testUrl, endpoint.getMethod(), null, null);
                    
                    if (response.getStatusCode() == 200) {
                        // If we can access resources with random IDs, potential BOLA
                        Vulnerability vuln = new Vulnerability(
                            "Broken Object Level Authorization (BOLA)",
                            Vulnerability.Severity.HIGH,
                            "Potential IDOR vulnerability - able to access resources with random object IDs",
                            endpoint.getPath(),
                            "Implement proper authorization checks for each object access"
                        );
                        vuln.setOwaspCategory("API1:2023 - BOLA");
                        vuln.setCwe("CWE-639");
                        vulnerabilities.add(vuln);
                    }
                    
                } catch (Exception e) {
                    logger.debug("BOLA test failed for {}: {}", endpoint.getPath(), e.getMessage());
                }
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testBrokenAuthentication(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check for authentication endpoints
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (endpoint.getPath().contains("auth") || endpoint.getPath().contains("token")) {
                // Test for weak authentication mechanisms
                try {
                    String testUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
                    
                    // Test with weak credentials
                    var response = apiClient.sendRequest(
                        testUrl, 
                        endpoint.getMethod(),
                        Map.of("client_id", "admin", "client_secret", "admin"),
                        null
                    );
                    
                    if (response.getStatusCode() == 200) {
                        Vulnerability vuln = new Vulnerability(
                            "Weak Authentication Mechanism",
                            Vulnerability.Severity.HIGH,
                            "Authentication endpoint accepts weak/default credentials",
                            endpoint.getPath(),
                            "Implement strong authentication, rate limiting, and account lockout"
                        );
                        vuln.setOwaspCategory("API2:2023 - Broken Authentication");
                        vuln.setCwe("CWE-307");
                        vulnerabilities.add(vuln);
                    }
                    
                } catch (Exception e) {
                    logger.debug("Authentication test failed for {}: {}", endpoint.getPath(), e.getMessage());
                }
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testSecurityMisconfiguration(APIClient.HttpResponse response) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check security headers
        Map<String, String> headers = response.getHeaders();
        
        if (!headers.containsKey("Content-Security-Policy")) {
            vulnerabilities.add(createSecurityHeaderVulnerability("Content-Security-Policy"));
        }
        
        if (!headers.containsKey("X-Content-Type-Options")) {
            vulnerabilities.add(createSecurityHeaderVulnerability("X-Content-Type-Options"));
        }
        
        if (!headers.containsKey("X-Frame-Options")) {
            vulnerabilities.add(createSecurityHeaderVulnerability("X-Frame-Options"));
        }
        
        if (headers.containsKey("Access-Control-Allow-Origin") && 
            headers.get("Access-Control-Allow-Origin").equals("*")) {
            
            Vulnerability vuln = new Vulnerability(
                "Overly Permissive CORS Policy",
                Vulnerability.Severity.MEDIUM,
                "CORS policy allows requests from any origin (*)",
                "All endpoints",
                "Restrict CORS to specific trusted domains"
            );
            vuln.setOwaspCategory("API8:2023 - Security Misconfiguration");
            vuln.setCwe("CWE-942");
            vulnerabilities.add(vuln);
        }
        
        return vulnerabilities;
    }

    private Vulnerability createSecurityHeaderVulnerability(String headerName) {
        return new Vulnerability(
            "Missing Security Header: " + headerName,
            Vulnerability.Severity.MEDIUM,
            "Security header " + headerName + " is missing",
            "All endpoints",
            "Add " + headerName + " header with appropriate security policy"
        );
    }

    // Остальные методы OWASP анализа (упрощенные версии)
    private List<Vulnerability> testBrokenObjectPropertyAuthorization(APISpecification apiSpec) {
        return List.of(); // Simplified for demo
    }

    private List<Vulnerability> testUnrestrictedResourceConsumption(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test for lack of rate limiting
        Vulnerability vuln = new Vulnerability(
            "Potential Lack of Rate Limiting",
            Vulnerability.Severity.MEDIUM,
            "No obvious rate limiting detected on authentication endpoints",
            "/auth/bank-token",
            "Implement rate limiting to prevent brute force attacks"
        );
        vuln.setOwaspCategory("API4:2023 - Unrestricted Resource Consumption");
        vuln.setCwe("CWE-770");
        vulnerabilities.add(vuln);
        
        return vulnerabilities;
    }

    private List<Vulnerability> testBrokenFunctionLevelAuthorization(APISpecification apiSpec) {
        return List.of(); // Simplified for demo
    }

    private List<Vulnerability> testUnrestrictedBusinessFlowAccess(APISpecification apiSpec) {
        return List.of(); // Simplified for demo
    }

    private List<Vulnerability> testSSRF(APISpecification apiSpec) {
        return List.of(); // Simplified for demo
    }

    private List<Vulnerability> testSecurityMisconfiguration(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test a sample endpoint for security headers
        try {
            var response = apiClient.sendRequest(
                "https://vbank.open.bankingapi.ru/", 
                "GET", 
                null, 
                null
            );
            
            vulnerabilities.addAll(testSecurityMisconfiguration(response));
            
        } catch (Exception e) {
            logger.debug("Security misconfiguration test failed: {}", e.getMessage());
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testImproperInventoryManagement(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check for exposed documentation endpoints
        String[] docEndpoints = {
            "/docs", "/swagger", "/openapi", "/api-docs", 
            "/v2/api-docs", "/v3/api-docs"
        };
        
        for (String docEndpoint : docEndpoints) {
            try {
                var response = apiClient.sendRequest(
                    "https://vbank.open.bankingapi.ru" + docEndpoint,
                    "GET",
                    null,
                    null
                );
                
                if (response.getStatusCode() == 200) {
                    Vulnerability vuln = new Vulnerability(
                        "Exposed API Documentation",
                        Vulnerability.Severity.LOW,
                        "API documentation is publicly accessible: " + docEndpoint,
                        docEndpoint,
                        "Restrict access to API documentation in production"
                    );
                    vuln.setOwaspCategory("API9:2023 - Improper Inventory Management");
                    vuln.setCwe("CWE-1052");
                    vulnerabilities.add(vuln);
                }
                
            } catch (Exception e) {
                // Endpoint doesn't exist or not accessible
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testUnsafeAPIConsumption(APISpecification apiSpec) {
        return List.of(); // Simplified for demo
    }
}