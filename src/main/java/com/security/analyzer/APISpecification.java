package com.security.analyzer.model;

import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class APISpecification {
    private String openapi;
    private Map<String, Object> info;
    private Map<String, Map<String, Object>> paths;
    private List<Endpoint> endpoints;

    // Геттеры и сеттеры
    public String getOpenapi() { return openapi; }
    public void setOpenapi(String openapi) { this.openapi = openapi; }

    public Map<String, Object> getInfo() { return info; }
    public void setInfo(Map<String, Object> info) { this.info = info; }

    public Map<String, Map<String, Object>> getPaths() { return paths; }
    public void setPaths(Map<String, Map<String, Object>> paths) { this.paths = paths; }

    public List<Endpoint> getEndpoints() { return endpoints; }
    public void setEndpoints(List<Endpoint> endpoints) { this.endpoints = endpoints; }
}