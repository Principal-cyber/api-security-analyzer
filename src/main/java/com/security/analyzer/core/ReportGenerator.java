package com.security.analyzer.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.security.analyzer.model.SecurityReport;
import com.security.analyzer.model.Vulnerability;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;

public class ReportGenerator {
    private static final Logger logger = LoggerFactory.getLogger(ReportGenerator.class);
    private final ObjectMapper objectMapper;

    public ReportGenerator() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        this.objectMapper.registerModule(new JavaTimeModule());
        this.objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    public void generateHtmlReport(SecurityReport report, String filename) {
        try {
            String htmlContent = buildHtmlReport(report);
            Files.write(Paths.get(filename), htmlContent.getBytes());
            logger.info("HTML report generated: {}", filename);
        } catch (IOException e) {
            logger.error("Failed to generate HTML report: {}", e.getMessage());
        }
    }

    public void generateJsonReport(SecurityReport report, String filename) {
        try {
            objectMapper.writeValue(new File(filename), report);
            logger.info("JSON report generated: {}", filename);
        } catch (Exception e) {
            logger.error("Failed to generate JSON report: {}", e.getMessage(), e);
        }
    }

    private String buildHtmlReport(SecurityReport report) {
        StringBuilder html = new StringBuilder();

        html.append("""
            <!DOCTYPE html>
            <html lang="ru">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>API Security Analysis Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
                    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; text-align: center; }
                    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
                    .stat-card { background: white; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #ddd; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    .stat-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
                    .vulnerability-item { background: #f8f9fa; padding: 20px; margin-bottom: 15px; border-radius: 8px; border-left: 5px solid #dc3545; }
                    .vulnerability-item.critical { border-left-color: #dc3545; background: #ffe6e6; }
                    .vulnerability-item.high { border-left-color: #fd7e14; background: #fff3cd; }
                    .vulnerability-item.medium { border-left-color: #ffc107; background: #fff3cd; }
                    .vulnerability-item.low { border-left-color: #28a745; background: #e6f4ea; }
                    .severity-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; margin-right: 10px; }
                    .severity-critical { background: #dc3545; }
                    .severity-high { background: #fd7e14; }
                    .severity-medium { background: #ffc107; color: black; }
                    .severity-low { background: #28a745; }
                    .progress-bar { width: 100%; height: 20px; background: #e9ecef; border-radius: 10px; overflow: hidden; margin: 10px 0; }
                    .progress-fill { height: 100%; transition: width 0.3s ease; }
                    .security-score { font-size: 3em; font-weight: bold; text-align: center; margin: 20px 0; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔒 API Security Analysis Report</h1>
                        <p>Automated Security Testing Results</p>
                    </div>
            """);

        // Summary Section
        html.append("""
            <div class="summary-section">
                <h2>📊 Executive Summary</h2>
                <div class="stats-grid">
            """);

        html.append(String.format("""
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div>Tested Endpoints</div>
            </div>
            """, report.getTestedEndpoints()));

        html.append(String.format("""
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div>Vulnerabilities Found</div>
            </div>
            """, report.getVulnerabilities().size()));

        html.append(String.format("""
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div>Critical Issues</div>
            </div>
            """, report.getVulnerabilityCountBySeverity(Vulnerability.Severity.CRITICAL)));

        html.append(String.format("""
            <div class="stat-card">
                <div class="stat-number">%d</div>
                <div>High Issues</div>
            </div>
            """, report.getVulnerabilityCountBySeverity(Vulnerability.Severity.HIGH)));

        html.append("</div>");

        // Security Score
        html.append(String.format("""
            <div class="security-score" style="color: %s;">%.1f/100</div>
            <div style="text-align: center; margin-bottom: 30px;">Overall Security Score</div>
            """, getScoreColor(report.getSecurityScore()), report.getSecurityScore()));

        // Vulnerabilities List
        html.append("""
            <h2>🛡️ Detected Vulnerabilities</h2>
            """);

        if (report.getVulnerabilities().isEmpty()) {
            html.append("""
                <div style="text-align: center; padding: 40px; background: #e6f4ea; border-radius: 8px;">
                    <h3 style="color: #28a745;">✅ No vulnerabilities detected!</h3>
                    <p>The API appears to be secure based on the tests performed.</p>
                </div>
                """);
        } else {
            for (Vulnerability vuln : report.getVulnerabilities()) {
                String severityClass = vuln.getSeverity().name().toLowerCase();
                html.append(String.format("""
                    <div class="vulnerability-item %s">
                        <div style="margin-bottom: 10px;">
                            <span class="severity-badge severity-%s">%s</span>
                            <strong style="font-size: 1.2em;">%s</strong>
                        </div>
                        <div><strong>Endpoint:</strong> %s</div>
                        <div><strong>Description:</strong> %s</div>
                        <div><strong>Recommendation:</strong> %s</div>
                    """,
                    severityClass, severityClass, vuln.getSeverity(),
                    vuln.getTitle(), vuln.getEndpoint(),
                    vuln.getDescription(), vuln.getRecommendation()));

                if (vuln.getPayload() != null && !vuln.getPayload().isEmpty()) {
                    html.append(String.format("""
                        <div><strong>Payload:</strong> <code>%s</code></div>
                        """, vuln.getPayload()));
                }

                html.append("</div>");
            }
        }

        // Footer
        html.append(String.format("""
            <div style="margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 8px; text-align: center;">
                <p><strong>Generated:</strong> %s</p>
                <p><strong>Target:</strong> %s</p>
                <p><strong>Execution Time:</strong> %d ms</p>
            </div>
            """, 
            report.getTimestamp().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")),
            report.getTargetUrl(),
            report.getExecutionTime()));

        html.append("""
                </div>
            </body>
            </html>
            """);

        return html.toString();
    }

    private String getScoreColor(double score) {
        if (score >= 80) return "#28a745";
        if (score >= 60) return "#ffc107";
        return "#dc3545";
    }
}
