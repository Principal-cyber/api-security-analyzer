package com.security.analyzer.model;

import java.util.List;
import java.util.Map;

public class Endpoint {
    private String path;
    private String method;
    private String operationId;
    private List<Parameter> parameters;
    private List<Map<String, Object>> security;
    private Map<String, Object> requestBody;

    // Конструкторы
    public Endpoint() {}

    public Endpoint(String path, String method) {
        this.path = path;
        this.method = method;
    }

    // Геттеры и сеттеры
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getOperationId() { return operationId; }
    public void setOperationId(String operationId) { this.operationId = operationId; }

    public List<Parameter> getParameters() { return parameters; }
    public void setParameters(List<Parameter> parameters) { this.parameters = parameters; }

    public List<Map<String, Object>> getSecurity() { return security; }
    public void setSecurity(List<Map<String, Object>> security) { this.security = security; }

    public Map<String, Object> getRequestBody() { return requestBody; }
    public void setRequestBody(Map<String, Object> requestBody) { this.requestBody = requestBody; }

    public static class Parameter {
        private String name;
        private String in;
        private boolean required;
        private Map<String, Object> schema;

        // Геттеры и сеттеры
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }

        public String getIn() { return in; }
        public void setIn(String in) { this.in = in; }

        public boolean isRequired() { return required; }
        public void setRequired(boolean required) { this.required = required; }

        public Map<String, Object> getSchema() { return schema; }
        public void setSchema(Map<String, Object> schema) { this.schema = schema; }
    }
}