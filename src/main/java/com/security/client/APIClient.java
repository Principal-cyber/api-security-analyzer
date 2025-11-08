package com.security.analyzer.client;

import okhttp3.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeUnit;

public class APIClient {
    private static final Logger logger = LoggerFactory.getLogger(APIClient.class);
    
    private final OkHttpClient client;
    
    public static class HttpResponse {
        private final int statusCode;
        private final String body;
        private final Map<String, String> headers;
        private final long responseTime;
        
        public HttpResponse(int statusCode, String body, Map<String, String> headers, long responseTime) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = headers;
            this.responseTime = responseTime;
        }
        
        // Геттеры
        public int getStatusCode() { return statusCode; }
        public String getBody() { return body; }
        public Map<String, String> getHeaders() { return headers; }
        public long getResponseTime() { return responseTime; }
    }
    
    public APIClient() {
        this.client = new OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(10, TimeUnit.SECONDS)
            .build();
    }
    
    public HttpResponse sendRequest(String url, String method, 
                                  Map<String, String> parameters, 
                                  Map<String, String> headers) {
        long startTime = System.currentTimeMillis();
        
        try {
            Request.Builder requestBuilder = new Request.Builder();
            
            // Build URL with parameters for GET requests
            if ("GET".equalsIgnoreCase(method) && parameters != null && !parameters.isEmpty()) {
                HttpUrl.Builder urlBuilder = HttpUrl.parse(url).newBuilder();
                parameters.forEach(urlBuilder::addQueryParameter);
                url = urlBuilder.build().toString();
            }
            
            requestBuilder.url(url);
            
            // Add headers
            if (headers != null) {
                headers.forEach(requestBuilder::addHeader);
            }
            
            // Add body for POST requests
            if ("POST".equalsIgnoreCase(method) && parameters != null && !parameters.isEmpty()) {
                FormBody.Builder formBuilder = new FormBody.Builder();
                parameters.forEach(formBuilder::add);
                requestBuilder.post(formBuilder.build());
            }
            
            Request request = requestBuilder.build();
            Response response = client.newCall(request).execute();
            
            long responseTime = System.currentTimeMillis() - startTime;
            
            return new HttpResponse(
                response.code(),
                response.body() != null ? response.body().string() : "",
                response.headers().toMultimap().entrySet().stream()
                    .collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey, 
                        e -> String.join(", ", e.getValue())
                    )),
                responseTime
            );
            
        } catch (IOException e) {
            logger.error("Request failed: {}", e.getMessage());
            long responseTime = System.currentTimeMillis() - startTime;
            return new HttpResponse(0, e.getMessage(), Map.of(), responseTime);
        }
    }
    
    public HttpResponse sendJsonRequest(String url, String method, 
                                      String jsonBody, 
                                      Map<String, String> headers) {
        long startTime = System.currentTimeMillis();
        
        try {
            Request.Builder requestBuilder = new Request.Builder().url(url);
            
            // Add headers
            if (headers != null) {
                headers.forEach(requestBuilder::addHeader);
            }
            
            // Add JSON body
            if (jsonBody != null) {
                MediaType JSON = MediaType.parse("application/json; charset=utf-8");
                RequestBody body = RequestBody.create(jsonBody, JSON);
                
                if ("POST".equalsIgnoreCase(method)) {
                    requestBuilder.post(body);
                } else if ("PUT".equalsIgnoreCase(method)) {
                    requestBuilder.put(body);
                }
            }
            
            Request request = requestBuilder.build();
            Response response = client.newCall(request).execute();
            
            long responseTime = System.currentTimeMillis() - startTime;
            
            return new HttpResponse(
                response.code(),
                response.body() != null ? response.body().string() : "",
                response.headers().toMultimap().entrySet().stream()
                    .collect(java.util.stream.Collectors.toMap(
                        Map.Entry::getKey, 
                        e -> String.join(", ", e.getValue())
                    )),
                responseTime
            );
            
        } catch (IOException e) {
            logger.error("JSON request failed: {}", e.getMessage());
            long responseTime = System.currentTimeMillis() - startTime;
            return new HttpResponse(0, e.getMessage(), Map.of(), responseTime);
        }
    }
}
