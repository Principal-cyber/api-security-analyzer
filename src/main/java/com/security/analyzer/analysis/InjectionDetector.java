package com.security.analyzer.analysis;

import com.security.analyzer.client.APIClient;
import com.security.analyzer.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class InjectionDetector {
    private static final Logger logger = LoggerFactory.getLogger(InjectionDetector.class);
    
    private final APIClient apiClient;
    private final List<String> sqlInjectionPayloads;
    private final List<String> xssPayloads;
    private final List<String> commandInjectionPayloads;
    private final List<String> pathTraversalPayloads;

    public InjectionDetector(APIClient apiClient) {
        this.apiClient = apiClient;
        this.sqlInjectionPayloads = loadSQLInjectionPayloads();
        this.xssPayloads = loadXSSPayloads();
        this.commandInjectionPayloads = loadCommandInjectionPayloads();
        this.pathTraversalPayloads = loadPathTraversalPayloads();
    }

    public List<Vulnerability> testInjectionVulnerabilities(APISpecification apiSpec) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        logger.info("Testing injection vulnerabilities...");
        
        for (Endpoint endpoint : apiSpec.getEndpoints()) {
            if (endpoint.getMethod().equalsIgnoreCase("GET") || 
                endpoint.getMethod().equalsIgnoreCase("POST")) {
                
                vulnerabilities.addAll(testSQLInjection(endpoint));
                vulnerabilities.addAll(testXSSInjection(endpoint));
                vulnerabilities.addAll(testCommandInjection(endpoint));
                vulnerabilities.addAll(testPathTraversal(endpoint));
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testSQLInjection(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        for (String payload : sqlInjectionPayloads) {
            try {
                String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
                long startTime = System.currentTimeMillis();
                
                var response = apiClient.sendRequest(
                    fullUrl, 
                    endpoint.getMethod(),
                    Map.of("test_param", payload),
                    null
                );
                
                long responseTime = System.currentTimeMillis() - startTime;
                
                // Analyze response for SQL injection indicators
                if (isSQLInjectionDetected(response, responseTime)) {
                    Vulnerability vuln = new Vulnerability(
                        "SQL Injection Vulnerability",
                        Vulnerability.Severity.HIGH,
                        "Potential SQL injection detected with payload: " + payload,
                        endpoint.getPath(),
                        "Implement parameterized queries and input validation"
                    );
                    vuln.setPayload(payload);
                    vuln.setHttpStatus(response.getStatusCode());
                    vuln.setResponseTime(responseTime);
                    vuln.setOwaspCategory("API8:2023 - Injection");
                    vuln.setCwe("CWE-89");
                    vulnerabilities.add(vuln);
                    logger.warn("SQL Injection detected at {} with payload: {}", 
                               endpoint.getPath(), payload);
                }
                
            } catch (Exception e) {
                logger.debug("SQL injection test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }
        
        return vulnerabilities;
    }

    private boolean isSQLInjectionDetected(APIClient.HttpResponse response, long responseTime) {
        // Check for SQL injection indicators
        String body = response.getBody().toLowerCase();
        
        return response.getStatusCode() == 500 || // Internal Server Error
               responseTime > 3000 || // Delayed response
               body.contains("sql") ||
               body.contains("database") ||
               body.contains("syntax") ||
               body.contains("mysql") ||
               body.contains("postgresql") ||
               body.contains("ora-") ||
               body.matches(".*[0-9]{4}.*error.*") || // Database error codes
               body.contains("driver") ||
               body.contains("odbc") ||
               body.contains("jdbc");
    }

    private List<Vulnerability> testXSSInjection(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        for (String payload : xssPayloads) {
            try {
                String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
                var response = apiClient.sendRequest(
                    fullUrl,
                    endpoint.getMethod(),
                    Map.of("test_param", payload),
                    null
                );
                
                // Check if payload is reflected in response
                if (response.getBody().contains(payload) && 
                    !isPayloadProperlyEncoded(response.getBody(), payload)) {
                    
                    Vulnerability vuln = new Vulnerability(
                        "Cross-Site Scripting (XSS)",
                        Vulnerability.Severity.MEDIUM,
                        "XSS payload reflected in response: " + payload,
                        endpoint.getPath(),
                        "Implement proper output encoding and Content Security Policy"
                    );
                    vuln.setPayload(payload);
                    vuln.setHttpStatus(response.getStatusCode());
                    vuln.setOwaspCategory("API7:2023 - XSS");
                    vuln.setCwe("CWE-79");
                    vulnerabilities.add(vuln);
                }
                
            } catch (Exception e) {
                logger.debug("XSS test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }
        
        return vulnerabilities;
    }

    private boolean isPayloadProperlyEncoded(String responseBody, String payload) {
        // Check if payload is properly HTML encoded
        String encodedPayload = payload
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
            
        return responseBody.contains(encodedPayload) && !responseBody.contains(payload);
    }

    private List<Vulnerability> testCommandInjection(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        for (String payload : commandInjectionPayloads) {
            try {
                String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
                long startTime = System.currentTimeMillis();
                
                var response = apiClient.sendRequest(
                    fullUrl,
                    endpoint.getMethod(), 
                    Map.of("test_param", payload),
                    null
                );
                
                long responseTime = System.currentTimeMillis() - startTime;
                
                // Check for command injection indicators
                if (responseTime > 5000 || // Long delay indicating command execution
                    response.getBody().toLowerCase().contains("bin") ||
                    response.getBody().toLowerCase().contains("root") ||
                    response.getBody().toLowerCase().contains("etc/passwd") ||
                    response.getStatusCode() == 500) {
                    
                    Vulnerability vuln = new Vulnerability(
                        "Command Injection",
                        Vulnerability.Severity.HIGH,
                        "Potential command injection with payload: " + payload,
                        endpoint.getPath(),
                        "Validate and sanitize all user inputs, use safe APIs for command execution"
                    );
                    vuln.setPayload(payload);
                    vuln.setHttpStatus(response.getStatusCode());
                    vuln.setResponseTime(responseTime);
                    vuln.setOwaspCategory("API8:2023 - Injection");
                    vuln.setCwe("CWE-78");
                    vulnerabilities.add(vuln);
                }
                
            } catch (Exception e) {
                logger.debug("Command injection test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }
        
        return vulnerabilities;
    }

    private List<Vulnerability> testPathTraversal(Endpoint endpoint) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        for (String payload : pathTraversalPayloads) {
            try {
                String fullUrl = "https://vbank.open.bankingapi.ru" + endpoint.getPath();
                var response = apiClient.sendRequest(
                    fullUrl,
                    endpoint.getMethod(),
                    Map.of("file", payload, "filename", payload),
                    null
                );
                
                // Check for path traversal indicators
                if (response.getBody().contains("etc/passwd") ||
                    response.getBody().contains("root:") ||
                    response.getBody().contains("boot.ini") ||
                    response.getBody().contains("windows/system32")) {
                    
                    Vulnerability vuln = new Vulnerability(
                        "Path Traversal",
                        Vulnerability.Severity.HIGH,
                        "Path traversal vulnerability detected: " + payload,
                        endpoint.getPath(),
                        "Validate file paths, use whitelists for allowed files"
                    );
                    vuln.setPayload(payload);
                    vuln.setHttpStatus(response.getStatusCode());
                    vuln.setOwaspCategory("API4:2023 - Path Traversal");
                    vuln.setCwe("CWE-22");
                    vulnerabilities.add(vuln);
                }
                
            } catch (Exception e) {
                logger.debug("Path traversal test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }
        
        return vulnerabilities;
    }

    private List<String> loadSQLInjectionPayloads() {
        return List.of(
            "' OR '1'='1",
            "' UNION SELECT 1,2,3--",
            "'; DROP TABLE users--", 
            "' OR 1=1--",
            "admin'--",
            "1' ORDER BY 1--",
            "' OR 'a'='a",
            "') OR ('a'='a"
        );
    }

    private List<String> loadXSSPayloads() {
        return List.of(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>"
        );
    }

    private List<String> loadCommandInjectionPayloads() {
        return List.of(
            "; ls -la",
            "| whoami", 
            "& dir",
            "&& cat /etc/passwd",
            "|| id"
        );
    }

    private List<String> loadPathTraversalPayloads() {
        return List.of(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd"
        );
    }
}