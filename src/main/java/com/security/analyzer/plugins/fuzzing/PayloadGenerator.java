package com.security.analyzer.plugins.fuzzing;

import java.util.List;

public class PayloadGenerator {
    
    public List<String> generateFuzzPayloads() {
        return List.of(
            // Very long strings
            "A".repeat(10000),
            "B".repeat(5000),
            
            // Special characters
            "!@#$%^&*()_+-=[]{}|;:,.<>?",
            
            // Unicode characters
            "🚀🤖👾",
            "测试测试",
            
            // Format string attacks
            "%s%s%s%s%s",
            "%n%n%n%n%n",
            
            // Number boundary tests
            "99999999999999999999",
            "-99999999999999999999",
            
            // Boolean confusion
            "true",
            "false",
            "null",
            "undefined",
            
            // Array/object confusion
            "[]",
            "{}",
            "[1,2,3]",
            "{\"key\":\"value\"}",
            
            // Command injection variations
            "$(id)",
            "`id`",
            "|id|",
            
            // Path traversal variations
            "....////....////etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            
            // SQL injection variations
            "1' OR '1'='1'--",
            "1; SELECT * FROM users",
            
            // XSS variations
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            
            // Buffer overflow attempts
            "A".repeat(100000),
            "\0\0\0\0\0\0\0",
            
            // JSON injections
            "{\"__proto__\": {\"isAdmin\": true}}",
            "{\"constructor\": {\"prototype\": {\"isAdmin\": true}}}",
            
            // XML injections
            "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
            
            // NoSQL injections
            "{\"$where\": \"this.credits == this.debits\"}",
            "{\"$ne\": null}",
            
            // Header injections
            "test\r\nInjected-Header: value",
            "test\\r\\nInjected-Header: value",
            
            // Encoding variations
            "%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e"
        );
    }
}