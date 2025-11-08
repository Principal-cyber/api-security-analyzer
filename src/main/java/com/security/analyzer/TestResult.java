package com.security.analyzer.model;

public class TestResult {
    private String testName;
    private boolean passed;
    private String details;
    private String evidence;

    // Конструкторы
    public TestResult() {}

    public TestResult(String testName, boolean passed, String details) {
        this.testName = testName;
        this.passed = passed;
        this.details = details;
    }

    // Геттеры и сеттеры
    public String getTestName() { return testName; }
    public void setTestName(String testName) { this.testName = testName; }

    public boolean isPassed() { return passed; }
    public void setPassed(boolean passed) { this.passed = passed; }

    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }

    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
}