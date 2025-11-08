package com.security.analyzer.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class SecurityReport {
    @JsonProperty("timestamp")
    private LocalDateTime timestamp;

    @JsonProperty("target_url")
    private String targetUrl;

    @JsonProperty("vulnerabilities")
    private List<Vulnerability> vulnerabilities;

    @JsonProperty("statistics")
    private Map<String, Object> statistics;

    @JsonProperty("security_score")
    private double securityScore;

    @JsonProperty("compliance_score")
    private double complianceScore;

    @JsonProperty("execution_time")
    private long executionTime;

    @JsonProperty("tested_endpoints")
    private int testedEndpoints;

    public SecurityReport() {
        this.timestamp = LocalDateTime.now();
        this.vulnerabilities = new ArrayList<>();
    }

    // Геттеры и сеттеры
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public List<Vulnerability> getVulnerabilities() { return vulnerabilities; }
    public void setVulnerabilities(List<Vulnerability> vulnerabilities) { this.vulnerabilities = vulnerabilities; }

    public Map<String, Object> getStatistics() { return statistics; }
    public void setStatistics(Map<String, Object> statistics) { this.statistics = statistics; }

    public double getSecurityScore() { return securityScore; }
    public void setSecurityScore(double securityScore) { this.securityScore = securityScore; }

    public double getComplianceScore() { return complianceScore; }
    public void setComplianceScore(double complianceScore) { this.complianceScore = complianceScore; }

    public long getExecutionTime() { return executionTime; }
    public void setExecutionTime(long executionTime) { this.executionTime = executionTime; }

    public int getTestedEndpoints() { return testedEndpoints; }
    public void setTestedEndpoints(int testedEndpoints) { this.testedEndpoints = testedEndpoints; }

    public void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    public int getVulnerabilityCountBySeverity(Vulnerability.Severity severity) {
        return (int) vulnerabilities.stream()
                .filter(v -> v.getSeverity() == severity)
                .count();
    }
}