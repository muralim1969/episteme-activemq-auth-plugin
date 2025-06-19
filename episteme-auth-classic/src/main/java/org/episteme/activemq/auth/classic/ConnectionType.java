package org.episteme.activemq.auth.classic;

enum ConnectionType {
    UNKNOWN("unknown"),
    TCP("tcp"),
    SSL("ssl"),
    SSL_CERTAUTH("ssl+clientauth"),
    WS("ws"),
    WSS("wss"), 
    WSS_CERTAUTH("wss+clientauth"),
    VM("vm"),
    NIO("nio"),
    HTTP("http"),
    HTTPS("https"),
    HTTPS_CERTAUTH("https+clientauth"),
    MQTT("mqtt"),
    MQTTS("mqtts"),
    MQTTS_CERTAUTH("mqtts+clientauth");
    
    private final String description;
    
    ConnectionType(String description) {
        this.description = description;
    }
    
    public String getDescription() {
        return description;
    }
    
    @Override
    public String toString() {
        return description;
    }
}