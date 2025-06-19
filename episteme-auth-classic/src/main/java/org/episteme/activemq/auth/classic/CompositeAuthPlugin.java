package org.episteme.activemq.auth.classic;

import org.apache.activemq.broker.Broker;
import org.apache.activemq.broker.BrokerPlugin;
import org.episteme.activemq.auth.core.AuthConfigLoader;
import org.episteme.activemq.auth.core.AuthPipeline;
import org.episteme.activemq.auth.core.ValidatorRegistry;

import java.io.IOException;
import java.util.Map;

public class CompositeAuthPlugin implements BrokerPlugin {

    private final Map<String, AuthPipeline> pipelines;

    public CompositeAuthPlugin() throws IOException {
        this(getDefaultConfigPath());
    }

    public CompositeAuthPlugin(String configPath) throws IOException {
        AuthConfigLoader loader = new AuthConfigLoader(configPath);
        ValidatorRegistry registry = new ValidatorRegistry(loader);
        this.pipelines = registry.buildPipelines();
    }

    @Override
    public Broker installPlugin(Broker broker) {
        return new CompositeAuthBrokerFilter(broker, pipelines);
    }

    private static String getDefaultConfigPath() {
        String base = System.getProperty("activemq.base", ".");
        return base + "/conf/auth-config.json";
    }
}