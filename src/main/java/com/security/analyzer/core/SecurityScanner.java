package com.security.analyzer.core;

import com.security.analyzer.analysis.*;
import com.security.analyzer.client.APIClient;
import com.security.analyzer.client.OpenAPIParser;
import com.security.analyzer.model.*;
import com.security.analyzer.plugins.fuzzing.FuzzingEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SecurityScanner {
    private static final Logger logger = LoggerFactory.getLogger(SecurityScanner.class);

    private final APIClient apiClient;
    private final OpenAPIParser openApiParser;
    private final OWASPAnalyzer owaspAnalyzer;
    private final InjectionDetector injectionDetector;
    private final AuthenticationAnalyzer authAnalyzer;
    private final AuthorizationAnalyzer authorizationAnalyzer;
    private final ComplianceValidator complianceValidator;
    private final FuzzingEngine fuzzingEngine;

    private final ExecutorService executorService;

    public SecurityScanner() {
        this.apiClient = new APIClient();
        this.openApiParser = new OpenAPIParser();
        this.owaspAnalyzer = new OWASPAnalyzer(apiClient);
        this.injectionDetector = new InjectionDetector(apiClient);
        this.authAnalyzer = new AuthenticationAnalyzer(apiClient);
        this.authorizationAnalyzer = new AuthorizationAnalyzer(apiClient);
        this.complianceValidator = new ComplianceValidator(apiClient);
        this.fuzzingEngine = new FuzzingEngine(apiClient);

        this.executorService = Executors.newFixedThreadPool(5);
    }

    public SecurityReport scan(String targetUrl, String openApiSpecUrl) {
        logger.info("Starting security scan for: {}", targetUrl);
        long startTime = System.currentTimeMillis();

        SecurityReport report = new SecurityReport();
        report.setTargetUrl(targetUrl);

        try {
            // 1. Parse OpenAPI specification
            APISpecification apiSpec = openApiParser.parseFromUrl(openApiSpecUrl);
            if (apiSpec.getEndpoints() != null) {
                report.setTestedEndpoints(apiSpec.getEndpoints().size());
            } else {
                report.setTestedEndpoints(0);
            }

            // 2. Run security tests
            List<Vulnerability> allVulnerabilities = new ArrayList<>();

            // Run tests sequentially for simplicity
            allVulnerabilities.addAll(owaspAnalyzer.analyzeOWASPTop10(apiSpec));
            allVulnerabilities.addAll(injectionDetector.testInjectionVulnerabilities(apiSpec));
            allVulnerabilities.addAll(authAnalyzer.testAuthenticationMechanisms(apiSpec));
            allVulnerabilities.addAll(authorizationAnalyzer.testAuthorization(apiSpec));
            allVulnerabilities.addAll(complianceValidator.validateCompliance(apiSpec));
            allVulnerabilities.addAll(fuzzingEngine.runFuzzingTests(apiSpec));

            // Add all vulnerabilities to report
            allVulnerabilities.forEach(report::addVulnerability);

            // 3. Calculate scores
            calculateScores(report);

            long endTime = System.currentTimeMillis();
            report.setExecutionTime(endTime - startTime);

            logger.info("Security scan completed. Found {} vulnerabilities.",
                       report.getVulnerabilities().size());

        } catch (Exception e) {
            logger.error("Error during security scan: {}", e.getMessage(), e);
            throw new RuntimeException("Security scan failed", e);
        }

        return report;
    }
    
    private void calculateScores(SecurityReport report) {
        int totalVulnerabilities = report.getVulnerabilities().size();
        int critical = report.getVulnerabilityCountBySeverity(Vulnerability.Severity.CRITICAL);
        int high = report.getVulnerabilityCountBySeverity(Vulnerability.Severity.HIGH);
        int medium = report.getVulnerabilityCountBySeverity(Vulnerability.Severity.MEDIUM);
        
        // Calculate security score (0-100)
        double penalty = (critical * 10) + (high * 5) + (medium * 2);
        double securityScore = Math.max(0, 100 - penalty);
        
        report.setSecurityScore(securityScore);
        report.setComplianceScore(calculateComplianceScore(report));
        
        // Set statistics
        report.setStatistics(Map.of(
            "total_vulnerabilities", totalVulnerabilities,
            "critical_vulnerabilities", critical,
            "high_vulnerabilities", high,
            "medium_vulnerabilities", medium,
            "low_vulnerabilities", report.getVulnerabilityCountBySeverity(Vulnerability.Severity.LOW)
        ));
    }
    
    private double calculateComplianceScore(SecurityReport report) {
        // Simplified compliance score calculation
        long complianceIssues = report.getVulnerabilities().stream()
                .filter(v -> v.getOwaspCategory() != null && 
                           v.getOwaspCategory().contains("Compliance"))
                .count();
        
        return Math.max(0, 100 - (complianceIssues * 5));
    }
    
    public void shutdown() {
        executorService.shutdown();
    }
}