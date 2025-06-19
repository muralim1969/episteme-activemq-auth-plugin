package org.episteme.activemq.auth.core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.episteme.activemq.auth.core.AuthConfigLoader.PipelinesConfig;
import org.episteme.activemq.auth.core.validators.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ValidatorRegistry {
	
	private static final Logger log = LoggerFactory.getLogger(ValidatorRegistry.class);
    private final AuthConfigLoader configLoader;
    private final Map<String, Supplier<AuthValidator>> registry = new HashMap<>();

    public ValidatorRegistry(AuthConfigLoader configLoader) {
        this.configLoader = configLoader;
        registerDefaults();
    }

    private void registerDefaults() {
        registry.put("ip-acl-validator", () -> new IpAclValidator(configLoader));
        registry.put("client-cert-validator", () -> new ClientCertValidator(configLoader));
        registry.put("jwt-validator", () -> new JwtValidator(configLoader));
    }

    public AuthValidator create(String name) {
        Supplier<AuthValidator> supplier = registry.get(name);
        if (supplier == null) {
            throw new IllegalArgumentException("Unknown validator: " + name);
        }
        return supplier.get();
    }
    /**
     * Build validation pipelines from the current configuration
     * @return Map of pipeline name to ValidationPipeline
     */
    /**
     * Build authentication pipelines from the current configuration
     * @return Map of pipeline name to AuthPipeline
     */
    public Map<String, AuthPipeline> buildPipelines() {
        Optional<PipelinesConfig> pipelinesConfig = configLoader.getPipelinesConfig();
        
        if (!pipelinesConfig.isPresent()) {
            log.warn("No pipeline configuration found");
            return Collections.emptyMap();
        }
        
        return buildPipelines(pipelinesConfig.get());
    }

    /**
     * Build authentication pipelines from a specific configuration
     * @param pipelinesConfig The pipeline configuration to use
     * @return Map of pipeline name to AuthPipeline
     */
    public Map<String, AuthPipeline> buildPipelines(PipelinesConfig pipelinesConfig) {
        if (pipelinesConfig == null || pipelinesConfig.pipelines == null) {
            log.warn("No pipeline configuration provided");
            return Collections.emptyMap();
        }
        
        Map<String, AuthPipeline> pipelines = new HashMap<>();
        
        pipelinesConfig.pipelines.forEach((pipelineName, validatorNames) -> {
            try {
                AuthPipeline pipeline = buildPipeline(pipelineName, validatorNames);
                pipelines.put(pipelineName, pipeline);
                log.info("Built authentication pipeline '{}' with {} validators", 
                        pipelineName, validatorNames.size());
            } catch (Exception e) {
                log.error("Failed to build pipeline '{}': {}", pipelineName, e.getMessage());
                // Continue building other pipelines even if one fails
            }
        });
        
        log.info("Successfully built {} authentication pipelines", pipelines.size());
        return Collections.unmodifiableMap(pipelines);
    }

    /**
     * Build a single authentication pipeline
     * @param pipelineName Name of the pipeline
     * @param validatorNames List of validator names to include (order matters!)
     * @return AuthPipeline instance
     */
    public AuthPipeline buildPipeline(String pipelineName, List<String> validatorNames) {
        if (pipelineName == null || pipelineName.trim().isEmpty()) {
            throw new IllegalArgumentException("Pipeline name cannot be null or empty");
        }
        
        if (validatorNames == null || validatorNames.isEmpty()) {
            throw new IllegalArgumentException("Validator names list cannot be null or empty for pipeline: " + pipelineName);
        }
        
        List<AuthValidator> validators = new ArrayList<>();
        
        for (String validatorName : validatorNames) {
            if (validatorName == null || validatorName.trim().isEmpty()) {
                log.warn("Skipping null/empty validator name in pipeline '{}'", pipelineName);
                continue;
            }
            
            try {
                AuthValidator validator = create(validatorName.trim());
                validators.add(validator);
                log.debug("Added validator '{}' to pipeline '{}' at position {}", 
                         validatorName, pipelineName, validators.size());
            } catch (IllegalArgumentException e) {
                String message = String.format("Validator '%s' not found in registry for pipeline '%s'", 
                                             validatorName, pipelineName);
                log.error(message);
                throw new IllegalStateException(message, e);
            }
        }
        
        if (validators.isEmpty()) {
            throw new IllegalStateException("No valid validators found for pipeline: " + pipelineName);
        }
        
        log.debug("Created pipeline '{}' with validators: {}", pipelineName, 
                 validators.stream().map(v -> v.getClass().getSimpleName()).collect(Collectors.toList()));
        
        return new AuthPipeline(validators);
    }
}