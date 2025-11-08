package com.security.analyzer.analysis;

import com.security.analyzer.client.APIClient;
import com.security.analyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class ComplianceValidator {
    private static final Logger logger = LoggerFactory.getLogger(ComplianceValidator.class);
    
    private final APIClient apiClient;

    public ComplianceValidator(APIClient apiClient) {
        this.apiClient = apiClient;
    }

    public List<Vulnerability> validateCompliance(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        logger.info("Validating API compliance...");
        
        vulnerabilities.addAll(validateOpenAPICompliance(apiSpec));
        vulnerabilities.addAll(validateErrorHandling(apiSpec));
        vulnerabilities.addAll(validateDataValidation(apiSpec));
        
        return vulnerabilities;
    }

    private List<Vulnerability> validateOpenAPICompliance(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check if OpenAPI version is specified
        if (apiSpec.getOpenapi() == null || apiSpec.getOpenapi().isEmpty()) {
            vulnerabilities.add(createComplianceVulnerability(
                "Missing OpenAPI Version",
                "OpenAPI specification version is not specified",
                "Specification"
            ));
        }
        
        // Check for required info fields
        if (apiSpec.getInfo() == null) {
            vulnerabilities.add(createComplianceVulnerability(
                "Missing API Information",
                "OpenAPI info section is missing",
                "Specification"
            ));
        } else {
            if (!apiSpec.getInfo().containsKey("title")) {
                vulnerabilities.add(createComplianceVulnerability(
                    "Missing API Title",
                    "OpenAPI info title is missing",
                    "Specification"
                ));
            }
            if (!apiSpec.getInfo().containsKey("version")) {
                vulnerabilities.add(createComplianceVulnerability(
                    "Missing API Version",
                    "OpenAPI info version is missing",
                    "Specification"
                ));
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> validateErrorHandling(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test error handling with invalid requests
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (endpoint.getMethod().equalsIgnoreCase("GET")) {
                vulnerabilities.addAll(testErrorHandling(endpoint));
                break; // Test just one endpoint for demo
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testErrorHandling(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath() + "/invalid_endpoint_123";
            
            var response = apiClient.sendRequest(fullUrl, "GET", null, null);
            
            // Check for proper error handling
            if (response.getStatusCode() == 500) {
                vulnerabilities.add(createComplianceVulnerability(
                    "Internal Server Error on Invalid Request",
                    "Server returns 500 instead of 4xx for invalid requests",
                    endpoint.getPath()
                ));
            }
            
            if (response.getBody().toLowerCase().contains("exception") ||
                response.getBody().toLowerCase().contains("stack trace")) {
                
                vulnerabilities.add(createComplianceVulnerability(
                    "Information Disclosure in Errors",
                    "Error responses contain stack traces or sensitive information",
                    endpoint.getPath()
                ));
            }
            
        } catch (Exception e) {
            logger.debug("Error handling test failed for {}: {}", endpoint.getPath(), e.getMessage());
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> validateDataValidation(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test data validation with invalid input types
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (endpoint.getParameters() != null && !endpoint.getParameters().isEmpty()) {
                vulnerabilities.addAll(testDataValidation(endpoint));
                break; // Test just one endpoint for demo
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testDataValidation(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
            
            // Test with invalid data types
            var response = apiClient.sendRequest(
                fullUrl,
                endpoint.getMethod(),
                Map.of("invalid_param", "<script>alert('xss')</script>"),
                null
            );
            
            // If server accepts obviously invalid input, potential validation issue
            if (response.getStatusCode() == 200) {
                vulnerabilities.add(createComplianceVulnerability(
                    "Weak Input Validation",
                    "Endpoint accepts potentially malicious input without validation",
                    endpoint.getPath()
                ));
            }
            
        } catch (Exception e) {
            logger.debug("Data validation test failed for {}: {}", endpoint.getPath(), e.getMessage());
        }
        
        return vulnerabilities;
    }

    private Vulnerability createComplianceVulnerability(String title, String description, String endpoint) {
        Vulnerability vuln = new Vulnerability(
            title,
            Vulnerability.Severity.MEDIUM,
            description,
            endpoint,
            "Ensure API complies with OpenAPI specifications and implements proper validation"
        );
        vuln.setOwaspCategory("Compliance");
        return vuln;
    }
}