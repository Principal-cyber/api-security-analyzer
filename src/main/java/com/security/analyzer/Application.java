package com.security.analyzer;

import com.security.analyzer.core.SecurityScanner;
import com.security.analyzer.core.ReportGenerator;
import com.security.analyzer.model.SecurityReport;
import com.security.analyzer.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

public class Application {
    private static final Logger logger = LoggerFactory.getLogger(Application.class);

    public static void main(String[] args) {
        logger.info("Starting API Security Analyzer...");

        if (args.length < 2) {
            printUsage();
            return;
        }
        String targetUrl = args[0];
        String openApiSpecUrl = args[1];

        SecurityScanner scanner = new SecurityScanner();

        try {
            // Run security scan
            logger.info("Scanning target: {}", targetUrl);
            SecurityReport report = scanner.scan(targetUrl, openApiSpecUrl);

            // Generate reports with unique names
            ReportGenerator reportGenerator = new ReportGenerator();
            String bankName = getBankName(targetUrl);
            String timestamp = java.time.LocalDateTime.now().format(
                java.time.format.DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));

            String htmlReportName = String.format("%s-security-report-%s.html", bankName, timestamp);
            String jsonReportName = String.format("%s-security-report-%s.json", bankName, timestamp);

            reportGenerator.generateHtmlReport(report, htmlReportName);
            reportGenerator.generateJsonReport(report, jsonReportName);

            // Print summary to console
            printSummary(report, htmlReportName, jsonReportName);

            logger.info("Security analysis completed successfully!");

        } catch (Exception e) {
            logger.error("Application error: {}", e.getMessage(), e);
            System.err.println("❌ Error: " + e.getMessage());
            System.exit(1);
        } finally {
            scanner.shutdown();
        }
    }

    private static String getBankName(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host != null) {
                if (host.contains("vbank")) return "vbank";
                if (host.contains("abank")) return "abank";
                if (host.contains("sbank")) return "sbank";
                // Извлекаем первое поддоменное имя
                String[] parts = host.split("\\.");
                if (parts.length > 1) {
                    return parts[0]; // Возвращает "vbank", "abank" и т.д.
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to extract bank name from URL: {}", url);
        }
        return "bank"; // fallback
    }

    private static void printUsage() {
        System.out.println("""
            🚀 API Security Analyzer - Usage
            ================================

            Usage: java -jar api-security-analyzer.jar <target-url> <openapi-spec-url>

            Examples:
            java -jar api-security-analyzer.jar https://vbank.open.bankingapi.ru https://vbank.open.bankingapi.ru/openapi.json
            java -jar api-security-analyzer.jar https://abank.open.bankingapi.ru https://abank.open.bankingapi.ru/openapi.json
            java -jar api-security-analyzer.jar https://sbank.open.bankingapi.ru https://sbank.open.bankingapi.ru/openapi.json

            This tool will:
            ✅ Test for OWASP API Security Top 10 vulnerabilities
            ✅ Check for SQL Injection, XSS, Command Injection
            ✅ Validate authentication and authorization
            ✅ Test security headers and configuration
            ✅ Generate HTML and JSON reports
            """);
    }

    private static void printSummary(SecurityReport report, String htmlReport, String jsonReport) {
        System.out.println("\n" + "=".repeat(70));
        System.out.println("🚀 API SECURITY ANALYSIS REPORT");
        System.out.println("=".repeat(70));
        System.out.printf("Target: %s\n", report.getTargetUrl());
        System.out.printf("Scan Time: %s\n", report.getTimestamp());
        System.out.printf("Execution Time: %d ms\n", report.getExecutionTime());
        System.out.printf("Tested Endpoints: %d\n", report.getTestedEndpoints());
        System.out.println("-".repeat(70));

        System.out.printf("Security Score: %.1f/100\n", report.getSecurityScore());
        System.out.printf("Compliance Score: %.1f/100\n", report.getComplianceScore());
        System.out.println("-".repeat(70));

        System.out.println("VULNERABILITY SUMMARY:");
        System.out.printf("Critical: %d\n", report.getVulnerabilityCountBySeverity(Vulnerability.Severity.CRITICAL));
        System.out.printf("High: %d\n", report.getVulnerabilityCountBySeverity(Vulnerability.Severity.HIGH));
        System.out.printf("Medium: %d\n", report.getVulnerabilityCountBySeverity(Vulnerability.Severity.MEDIUM));
        System.out.printf("Low: %d\n", report.getVulnerabilityCountBySeverity(Vulnerability.Severity.LOW));
        System.out.printf("Total: %d\n", report.getVulnerabilities().size());
        System.out.println("=".repeat(70));

        // Print top vulnerabilities
        if (!report.getVulnerabilities().isEmpty()) {
            System.out.println("\n🔍 TOP VULNERABILITIES:");
            report.getVulnerabilities().stream()
                .filter(v -> v.getSeverity().ordinal() <= Vulnerability.Severity.HIGH.ordinal())
                .limit(5)
                .forEach(v -> System.out.printf("• [%s] %s - %s\n",
                    v.getSeverity(), v.getTitle(), v.getEndpoint()));
        }

        System.out.println("\n📊 Reports generated:");
        System.out.println("• " + htmlReport + " (Detailed HTML report)");
        System.out.println("• " + jsonReport + " (Machine-readable JSON)");
        System.out.println("\n🎯 Next steps: Review the reports and address critical issues first!");
    }
}