package org.episteme.activemq.auth.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import org.episteme.activemq.auth.core.utils.IpAclEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthConfigLoader  {
    
    private static final Logger log = LoggerFactory.getLogger(AuthConfigLoader.class);
    private final Path configPath;
    private final AtomicReference<RootConfig> configRef = new AtomicReference<>();
    private final ObjectMapper objectMapper = new ObjectMapper();  

    public AuthConfigLoader(String pathToConfigFile) throws IOException {
        this.configPath = Paths.get(pathToConfigFile).toAbsolutePath();
        loadConfig();
     }

    // Thread-safe getters with null safety
    public Optional<IpAclConfig> getIpAclConfig() {
        RootConfig config = configRef.get();
        return config != null ? Optional.ofNullable(config.ipAcl) : Optional.empty();
    }

    public Optional<CertConfig> getCertConfig() {
        RootConfig config = configRef.get();
        return config != null ? Optional.ofNullable(config.cert) : Optional.empty();
    }

    public Optional<JwtConfig> getJwtConfig() {
        RootConfig config = configRef.get();
        return config != null ? Optional.ofNullable(config.jwt) : Optional.empty();
    }

    public Optional<PipelinesConfig> getPipelinesConfig() {
        RootConfig config = configRef.get();
        return config != null ? Optional.ofNullable(config.pipelines) : Optional.empty();
    }

    // Get entire config atomically
    public RootConfig getConfig() {
        return configRef.get();
    }
    
    public List<String> getAllowedThumbprints() {
    	List<String> thumbprints = getCertConfig()
    		    .map(config -> config.allowedThumbprints)
    		    .orElse(Collections.emptyList());
    	return thumbprints;
    }
    
	public List<IpAclEntry> getIpAclAllowList() {
		List<IpAclEntry> allowList = getIpAclConfig()
			    .map(ipConfig -> ipConfig.allow)
			    .orElse(Collections.emptyList());
		return allowList;
	}
	
    private void loadConfig() throws IOException {
        log.debug("Loading configuration from: {}", configPath);
        
        if (!Files.exists(configPath)) {
            throw new IOException("Configuration file does not exist: " + configPath);
        }
        
        if (!Files.isReadable(configPath)) {
            throw new IOException("Configuration file is not readable: " + configPath);
        }

        try {
            JsonNode rootNode = objectMapper.readTree(Files.newBufferedReader(configPath));
            RootConfig parsed = new RootConfig();

            // Parse all sections
            parsed.ipAcl = parseIpAclConfig(rootNode.get("ipAcl"));
            parsed.cert = parseCertConfig(rootNode.get("cert"));
            parsed.jwt = parseJwtConfig(rootNode.get("jwt"));
            parsed.pipelines= parsePipelinesConfig(rootNode.get("pipelines"));

            // Validate configuration
            validateConfig(parsed);
            
            configRef.set(parsed);
            log.info("Configuration loaded successfully from: {}", configPath);
            
        } catch (Exception e) {
            log.error("Failed to load configuration from: {}", configPath, e);
            throw new IOException("Failed to load configuration", e);
        }
    }

    private void validateConfig(RootConfig config) {
        // Basic validation - ensure at least one auth method is configured
        boolean hasAuth = (config.ipAcl != null && config.ipAcl.allow != null && !config.ipAcl.allow.isEmpty()) ||
                         (config.cert != null && config.cert.allowedThumbprints != null && !config.cert.allowedThumbprints.isEmpty()) ||
                         (config.jwt != null && config.jwt.idps != null && !config.jwt.idps.isEmpty());
        
        if (!hasAuth) {
            log.warn("No authentication methods configured - service may be insecure");
        }
        
        // Validate JWT configurations
        if (config.jwt != null && config.jwt.idps != null) {
            config.jwt.idps.forEach((name, idpConfig) -> {
                if (idpConfig.issuer == null || idpConfig.issuer.trim().isEmpty()) {
                    log.warn("JWT IDP '{}' has empty issuer", name);
                }                
            });
        }
    }

    private IpAclConfig parseIpAclConfig(JsonNode ipAclNode) {
        if (ipAclNode == null) return null;
        
        JsonNode allowNode = ipAclNode.get("allow");
        if (allowNode == null || !allowNode.isArray() || allowNode.size() == 0) return null;

        List<IpAclEntry> allowList = new ArrayList<>(allowNode.size());
        allowNode.forEach(entry -> {
            String ipEntry = entry.asText();
            if (ipEntry != null && !ipEntry.trim().isEmpty()) {
                try {
                    allowList.add(IpAclEntry.parse(ipEntry.trim()));
                } catch (Exception e) {
                    log.warn("Invalid IP ACL entry '{}': {}", ipEntry, e.getMessage());
                }
            }
        });

        if (allowList.isEmpty()) {
            log.warn("IP ACL section present but no valid entries found");
            return null;
        }
        
        IpAclConfig config = new IpAclConfig();
        config.allow = Collections.unmodifiableList(allowList); // Make immutable
        log.debug("Loaded {} IP ACL entries", allowList.size());
        return config;
    }

    private CertConfig parseCertConfig(JsonNode certNode) {
        if (certNode == null) return null;
        
        JsonNode thumbprintsNode = certNode.get("allowedThumbprints");
        if (thumbprintsNode == null || !thumbprintsNode.isArray() || thumbprintsNode.size() == 0) return null;

        List<String> thumbprints = new ArrayList<>(thumbprintsNode.size());
        thumbprintsNode.forEach(node -> {
            String thumbprint = node.asText();
            if (thumbprint != null && !thumbprint.trim().isEmpty()) {
                // Normalize thumbprint format (remove spaces, convert to uppercase)
                String normalized = thumbprint.trim()
                					.replaceAll("\\s+", "")
                					.replaceAll(":", "")
                					.toUpperCase();
                if (isValidThumbprint(normalized)) {
                    thumbprints.add(normalized);
                } else {
                    log.warn("Invalid certificate thumbprint format: {}", thumbprint);
                }
            }
        });
        
        if (thumbprints.isEmpty()) {
            log.warn("Certificate section present but no valid thumbprints found");
            return null;
        }
        
        CertConfig config = new CertConfig();
        config.allowedThumbprints = Collections.unmodifiableList(thumbprints); // Make immutable
        log.debug("Loaded {} certificate thumbprints", thumbprints.size());
        return config;
    }

    private boolean isValidThumbprint(String thumbprint) {
        // Basic validation for SHA-1 thumbprint (40 hex chars with optional colons)
        return thumbprint.matches("^[0-9A-F]{40}$") || thumbprint.matches("^([0-9A-F]{2}:){19}[0-9A-F]{2}$");
    }

    private JwtConfig parseJwtConfig(JsonNode jwtNode) {
        if (jwtNode == null) return null;
        
        JsonNode idpsNode = jwtNode.get("idps");
        if (idpsNode == null || !idpsNode.isObject() || idpsNode.size() == 0) return null;

        Map<String, JwtIdpConfig> idps = new HashMap<>(idpsNode.size());
        idpsNode.fields().forEachRemaining(entry -> {
            String idpName = entry.getKey();
            if (idpName != null && !idpName.trim().isEmpty()) {
                try {
                    JwtIdpConfig cfg = objectMapper.convertValue(entry.getValue(), JwtIdpConfig.class);
                    if (cfg != null && isValidJwtIdpConfig(cfg)) {
                        idps.put(cfg.issuer.trim().toLowerCase(), cfg);
                    } else {
                        log.warn("Invalid JWT IDP configuration for: {}", idpName);
                    }
                } catch (Exception e) {
                    log.warn("Failed to parse JWT IDP config for '{}': {}", idpName, e.getMessage());
                }
            }
        });

        if (idps.isEmpty()) {
            log.warn("JWT section present but no valid IDP configurations found");
            return null;
        }
        
        JwtConfig config = new JwtConfig();
        config.idps = Collections.unmodifiableMap(idps); // Make immutable
        log.debug("Loaded {} JWT identity providers", idps.size());
        return config;
    }

    private boolean isValidJwtIdpConfig(JwtIdpConfig config) {
        return config.issuer != null && !config.issuer.trim().isEmpty() ;
              
    }

    private PipelinesConfig parsePipelinesConfig(JsonNode pipelinesNode) {
        if (pipelinesNode == null) return null;
        
        try {
            // The JSON structure is: { "pipelines": { "default": [...], "stomp": [...] } }
            // But the pipelinesNode is already the inner object: { "default": [...], "stomp": [...] }
            
            if (!pipelinesNode.isObject() || pipelinesNode.size() == 0) {
                return null;
            }

            Map<String, List<String>> pipelines = new HashMap<>();
            
            pipelinesNode.fields().forEachRemaining(entry -> {
                String pipelineName = entry.getKey();
                JsonNode validatorsNode = entry.getValue();
                
                if (pipelineName != null && !pipelineName.trim().isEmpty() && 
                    validatorsNode != null && validatorsNode.isArray()) {
                    
                    List<String> validators = new ArrayList<>();
                    validatorsNode.forEach(validatorNode -> {
                        String validatorName = validatorNode.asText();
                        if (validatorName != null && !validatorName.trim().isEmpty()) {
                            validators.add(validatorName.trim());
                        }
                    });
                    
                    if (!validators.isEmpty()) {
                        pipelines.put(pipelineName.trim(), Collections.unmodifiableList(validators));
                    }
                }
            });
            
            if (pipelines.isEmpty()) {
                log.warn("Pipelines section present but no valid pipeline configurations found");
                return null;
            }
            
            PipelinesConfig config = new PipelinesConfig();
            config.pipelines = Collections.unmodifiableMap(pipelines);
            log.debug("Loaded {} pipeline configurations", pipelines.size());
            return config;
            
        } catch (Exception e) {
            log.error("Failed to parse pipelines configuration: {}", e.getMessage(), e);
            return null;
        }
    }
    // Inner classes remain the same but with immutable collections
    public static class RootConfig {
        public IpAclConfig ipAcl;
        public CertConfig cert;
        public JwtConfig jwt;
        public PipelinesConfig pipelines;
    }

    public static class IpAclConfig {
        public List<IpAclEntry> allow;
    }

    public static class CertConfig {
        public List<String> allowedThumbprints;
    }

    public static class JwtConfig {
        public Map<String, JwtIdpConfig> idps;
    }

    public static class JwtIdpConfig {
        public String issuer;
        public String[] audience;
    }
    
    public static class PipelinesConfig {
        public Map<String, List<String>> pipelines;
    }

}