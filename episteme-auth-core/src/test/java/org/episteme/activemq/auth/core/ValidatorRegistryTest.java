package org.episteme.activemq.auth.core;

import org.junit.jupiter.api.*;

import static org.junit.jupiter.api.Assertions.*;

import org.episteme.activemq.auth.core.validators.*;

class ValidatorRegistryTest {

    private AuthConfigLoader configLoader;
    private ValidatorRegistry validatorRegistry;

    @BeforeEach
    void setUp() throws Exception {
        
        configLoader = createTestConfigLoader();
        validatorRegistry = new ValidatorRegistry(configLoader);
    }

    @AfterEach
    void tearDown() throws Exception {       
    }

    private AuthConfigLoader createTestConfigLoader() throws Exception {
    	return configLoader = new AuthConfigLoader("src/test/resources/valid-complete-config.json");
    }

    @Test
    @DisplayName("Should create IP ACL validator successfully")
    void shouldCreateIpAclValidator() {
        // When
        AuthValidator validator = validatorRegistry.create("ip-acl-validator");

        // Then
        assertNotNull(validator);
        assertTrue(validator instanceof IpAclValidator);
    }

    @Test
    @DisplayName("Should create client cert validator successfully")
    void shouldCreateClientCertValidator() {
        // When
        AuthValidator validator = validatorRegistry.create("client-cert-validator");

        // Then
        assertNotNull(validator);
        assertTrue(validator instanceof ClientCertValidator);
    }

    @Test
    @DisplayName("Should create JWT validator successfully")
    void shouldCreateJwtValidator() {
        // When
        AuthValidator validator = validatorRegistry.create("jwt-validator");

        // Then
        assertNotNull(validator);
        assertTrue(validator instanceof JwtValidator);
    }

    @Test
    @DisplayName("Should throw exception for unknown validator")
    void shouldThrowExceptionForUnknownValidator() {
        // When & Then
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> validatorRegistry.create("unknown-validator")
        );

        assertEquals("Unknown validator: unknown-validator", exception.getMessage());
    }

    @Test
    @DisplayName("Should create new validator instances on each call")
    void shouldCreateNewValidatorInstancesOnEachCall() {
        // When
        AuthValidator validator1 = validatorRegistry.create("ip-acl-validator");
        AuthValidator validator2 = validatorRegistry.create("ip-acl-validator");

        // Then
        assertNotNull(validator1);
        assertNotNull(validator2);
        assertNotSame(validator1, validator2); // Should be different instances
        assertEquals(validator1.getClass(), validator2.getClass()); // But same type
    }
}