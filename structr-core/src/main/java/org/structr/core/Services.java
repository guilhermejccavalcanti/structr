/**
 * Copyright (C) 2010-2014 Morgner UG (haftungsbeschr�nkt)
 *
 * This file is part of Structr <http://structr.org>.
 *
 * Structr is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * Structr is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Structr.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.structr.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Node;
import org.neo4j.graphdb.Relationship;
import org.neo4j.tooling.GlobalGraphOperations;
import org.structr.common.SecurityContext;
import org.structr.common.StructrConf;
import org.structr.core.app.App;
import org.structr.core.app.StructrApp;
import org.structr.core.graph.NodeFactory;
import org.structr.core.graph.NodeInterface;
import org.structr.core.graph.NodeService;
import org.structr.core.graph.RelationshipFactory;
import org.structr.core.graph.RelationshipInterface;
import org.structr.core.graph.Tx;
import org.structr.core.property.StringProperty;
import org.structr.module.JarConfigurationProvider;
import org.structr.schema.ConfigurationProvider;

/**
 * Provides access to the service layer in structr.
 *
 * Use the command method to obtain an instance of the desired command.
 *
 * @author Christian Morgner
 */
public class Services {

    private static final Logger logger = Logger.getLogger(StructrApp.class.getName());

    private static StructrConf baseConf = null;

    // Configuration constants
    public static final String INITIAL_SEED_FILE = "seed.zip";

    public static final String BASE_PATH = "base.path";

    public static final String CONFIGURED_SERVICES = "configured.services";

    public static final String CONFIG_FILE_PATH = "configfile.path";

    public static final String DATABASE_PATH = "database.path";

    public static final String FILES_PATH = "files.path";

    public static final String DATA_EXCHANGE_PATH = "data.exchange.path";

    public static final String LOG_DATABASE_PATH = "log.database.path";

    public static final String FOREIGN_TYPE = "foreign.type.key";

    public static final String NEO4J_SHELL_ENABLED = "neo4j.shell.enabled";

    public static final String NEO4J_SHELL_PORT = "neo4j.shell.port";

    public static final String LOG_SERVICE_INTERVAL = "structr.logging.interval";

    public static final String LOG_SERVICE_THRESHOLD = "structr.logging.threshold";

    public static final String SERVER_IP = "server.ip";

    public static final String SMTP_HOST = "smtp.host";

    public static final String SMTP_PORT = "smtp.port";

    public static final String SMTP_USER = "smtp.user";

    public static final String SMTP_PASSWORD = "smtp.password";

    public static final String SMTP_USE_TLS = "smtp.tls.enabled";

    public static final String SMTP_REQUIRE_TLS = "smtp.tls.required";

    public static final String SUPERUSER_USERNAME = "superuser.username";

    public static final String SUPERUSER_PASSWORD = "superuser.password";

    public static final String TCP_PORT = "tcp.port";

    public static final String TMP_PATH = "tmp.path";

    public static final String UDP_PORT = "udp.port";

    public static final String JSON_INDENTATION = "json.indentation";

    public static final String JSON_REDUNDANCY_REDUCTION = "json.redundancyReduction";

    public static final String GEOCODING_PROVIDER = "geocoding.provider";

    public static final String GEOCODING_LANGUAGE = "geocoding.language";

    public static final String GEOCODING_APIKEY = "geocoding.apikey";

    public static final String CONFIGURATION = "configuration.provider";

    public static final String TESTING = "testing";

    public static final String MIGRATION_KEY = "NodeService.migration";

    public static final String ACCESS_CONTROL_MAX_AGE = "access.control.max.age";

    public static final String ACCESS_CONTROL_ALLOW_METHODS = "access.control.allow.methods";

    public static final String ACCESS_CONTROL_ALLOW_HEADERS = "access.control.allow.headers";

    public static final String ACCESS_CONTROL_ALLOW_CREDENTIALS = "access.control.allow.credentials";

    public static final String ACCESS_CONTROL_EXPOSE_HEADERS = "access.control.expose.headers";

    public static final String APPLICATION_SESSION_TIMEOUT = "application.session.timeout";

    // singleton instance
    private static int globalSessionTimeout = -1;

    private static Services singletonInstance = null;

    // non-static members
    private final Map<String, Object> attributes = new ConcurrentHashMap<>(10, 0.9f, 8);

    private final Map<Class, Service> serviceCache = new ConcurrentHashMap<>(10, 0.9f, 8);

    private final Set<Class> registeredServiceClasses = new LinkedHashSet<>();

    private final Set<String> configuredServiceClasses = new LinkedHashSet<>();

    private StructrConf structrConf = new StructrConf();

    private ConfigurationProvider configuration = null;

    private boolean initializationDone = false;

    private boolean shutdownDone = false;

    private String configuredServiceNames = null;

    private String configurationClass = null;

    private Services() {
    }

    public static Services getInstance() {
        if (singletonInstance == null) {
            singletonInstance = new Services();
            singletonInstance.initialize();
        }
        return singletonInstance;
    }

    public static Services getInstance(final StructrConf properties) {
        if (singletonInstance == null) {
            singletonInstance = new Services();
            singletonInstance.initialize(properties);
        }
        return singletonInstance;
    }

    /**
	 * Creates and returns a command of the given <code>type</code>. If a command is
	 * found, the corresponding service will be discovered and activated.
	 *
	 * @param <T>
	 * @param securityContext
	 * @param commandType the runtime type of the desired command
	 * @return the command
	 */
    public <T extends Command> T command(SecurityContext securityContext, Class<T> commandType) {
        Class serviceClass = null;
        T command = null;
        try {
            command = commandType.newInstance();
            command.setSecurityContext(securityContext);
            serviceClass = command.getServiceClass();
            if ((serviceClass != null) && configuredServiceClasses.contains(serviceClass.getSimpleName())) {
                Service service = serviceCache.get(serviceClass);
                if (service == null) {
                    service = createService(serviceClass);
                } else {
                    if (service instanceof RunnableService) {
                        RunnableService runnableService = (RunnableService) service;
                        if (!runnableService.isRunning()) {
                            runnableService.stopService();
                            runnableService.shutdown();
                            service = createService(serviceClass);
                        }
                    }
                }
                logger.log(Level.FINEST, "Initializing command ", commandType.getName());
                service.injectArguments(command);
            }
        } catch (Throwable t) {
            t.printStackTrace();
            logger.log(Level.SEVERE, "Exception while creating command " + commandType.getName(), t);
        }
        return (command);
    }

    private void initialize() {
        final StructrConf config = getBaseConfiguration();
        final String configTemplateFileName = "structr.conf_templ";
        final String configFileName = "structr.conf";
        final File configTemplateFile = new File(configTemplateFileName);
        final File configFile = new File(configFileName);
        if (!configFile.exists() && !configTemplateFile.exists()) {
            logger.log(Level.SEVERE, "Unable to create config file, {0} and {1} do not exist, aborting. Please create a {0} configuration file and try again.", new Object[] { configFileName, configTemplateFileName });
            System.exit(1);
        }
        if (!configFile.exists() && configTemplateFile.exists()) {
            logger.log(Level.WARNING, "Configuration file {0} not found, copying from template {1}. Please adapt newly created {0} to your needs.", new Object[] { configFileName, configTemplateFileName });
            try {
                Files.copy(configTemplateFile.toPath(), configFile.toPath());
            } catch (IOException ioex) {
                logger.log(Level.SEVERE, "Unable to create config file, copying of template failed.", ioex);
                System.exit(1);
            }
        }
        logger.log(Level.INFO, "Reading {0}..", configFileName);
        try {
            PropertiesConfiguration.setDefaultListDelimiter(' ');
            final PropertiesConfiguration propConf = new PropertiesConfiguration(configFileName);
            structrConf.load(propConf);
        } catch (ConfigurationException ex) {
            logger.log(Level.SEVERE, null, ex);
        }
        mergeConfiguration(config, structrConf);
        initialize(config);
    }

    private void initialize(final StructrConf properties) {
        this.structrConf = properties;
        configurationClass = properties.getProperty(Services.CONFIGURATION);
        configuredServiceNames = properties.getProperty(Services.CONFIGURED_SERVICES);
        configuredServiceClasses.addAll(Arrays.asList(configuredServiceNames.split("[ ,]+")));
        getConfigurationProvider();
        logger.log(Level.INFO, "Starting services");
        for (final String serviceClassName : configuredServiceClasses) {
            Class serviceClass = getServiceClassForName(serviceClassName);
            if (serviceClass != null) {
                try {
                    final Service service = createService(serviceClass);
                    if (service != null) {
                        service.initialized();
                    } else {
                        logger.log(Level.WARNING, "Service {0} was not started!", serviceClassName);
                    }
                } catch (Throwable t) {
                    logger.log(Level.WARNING, "Exception while registering service {0}: {1}", new Object[] { serviceClassName, t });
                    t.printStackTrace();
                }
            }
        }
        logger.log(Level.INFO, "{0} service(s) processed", serviceCache.size());
        registeredServiceClasses.clear();
        if (getService(NodeService.class) != null) {
            if ("true".equals(properties.getProperty(Services.MIGRATION_KEY))) {
                migrateDatabase();
            }
        }
        logger.log(Level.INFO, "Registering shutdown hook.");
        Runtime.getRuntime().addShutdownHook(new Thread() {

            @Override
            public void run() {
                shutdown();
            }
        });
        logger.log(Level.INFO, "Initialization complete");
        initializationDone = true;
    }

    public boolean isInitialized() {
        return initializationDone;
    }

    public void shutdown() {
        initializationDone = false;
        if (!shutdownDone) {
            System.out.println("INFO: Shutting down...");
            for (Service service : serviceCache.values()) {
                try {
                    if (service instanceof RunnableService) {
                        RunnableService runnableService = (RunnableService) service;
                        if (runnableService.isRunning()) {
                            runnableService.stopService();
                        }
                    }
                    service.shutdown();
                } catch (Throwable t) {
                    System.out.println("WARNING: Failed to shut down " + service.getName() + ": " + t.getMessage());
                }
            }
            serviceCache.clear();
            configuration.shutdown();
            singletonInstance = null;
            System.out.println("INFO: Shutdown complete");
            shutdownDone = true;
        }
    }

    /**
	 * Registers a service, enabling the service layer to automatically start
	 * autorun servies.
	 *
	 * @param serviceClass the service class to register
	 */
    public void registerServiceClass(Class serviceClass) {
        registeredServiceClasses.add(serviceClass);
    }

    public String getConfigurationValue(String key) {
        return getConfigurationValue(key, null);
    }

    public String getConfigurationValue(String key, String defaultValue) {
        return getCurrentConfig().getProperty(key, defaultValue);
    }

    public Class getServiceClassForName(final String serviceClassName) {
        for (Class serviceClass : registeredServiceClasses) {
            if (serviceClass.getSimpleName().equals(serviceClassName)) {
                return serviceClass;
            }
        }
        return null;
    }

    public ConfigurationProvider getConfigurationProvider() {
        if (configuration == null) {
            try {
                configuration = (ConfigurationProvider) Class.forName(configurationClass).newInstance();
                configuration.initialize();
            } catch (Throwable t) {
                t.printStackTrace();
                logger.log(Level.SEVERE, "Unable to instantiate schema provider of type {0}: {1}", new Object[] { configurationClass, t.getMessage() });
            }
        }
        return configuration;
    }

    /**
	 * Store an attribute value in the service config
	 *
	 * @param name
	 * @param value
	 */
    public void setAttribute(final String name, final Object value) {
        synchronized (attributes) {
            attributes.put(name, value);
        }
    }

    /**
	 * Retrieve attribute value from service config
	 *
	 * @param name
	 * @return attribute
	 */
    public Object getAttribute(final String name) {
        return attributes.get(name);
    }

    /**
	 * Remove attribute value from service config
	 *
	 * @param name
	 */
    public void removeAttribute(final String name) {
        attributes.remove(name);
    }

    private Service createService(Class serviceClass) {
        logger.log(Level.FINE, "Creating service ", serviceClass.getName());
        Service service = null;
        try {
            service = (Service) serviceClass.newInstance();
            service.initialize(getCurrentConfig());
            if (service instanceof RunnableService) {
                RunnableService runnableService = (RunnableService) service;
                if (runnableService.runOnStartup()) {
                    logger.log(Level.FINER, "Starting RunnableService instance ", serviceClass.getName());
                    runnableService.startService();
                    serviceCache.put(serviceClass, service);
                }
            } else {
                if (service instanceof SingletonService) {
                    serviceCache.put(serviceClass, service);
                }
            }
        } catch (Throwable t) {
            t.printStackTrace();
            if (service.isVital()) {
                logger.log(Level.SEVERE, "Vital service {0} failed to start: {1}. Aborting", new Object[] { service.getClass().getSimpleName(), t.getMessage() });
                System.exit(1);
            } else {
                logger.log(Level.SEVERE, "Service {0} failed to start: {1}.", new Object[] { service.getClass().getSimpleName(), t.getMessage() });
            }
        }
        return service;
    }

    /**
	 * Return all registered services
	 *
	 * @return list of services
	 */
    public List<Service> getServices() {
        List<Service> services = new LinkedList<>();
        for (Service service : serviceCache.values()) {
            services.add(service);
        }
        return services;
    }

    public <T extends Service> T getService(final Class<T> type) {
        return (T) serviceCache.get(type);
    }

    public String getConfigValue(final Map<String, String> config, final String key, final String defaultValue) {
        String value = StringUtils.strip(config.get(key));
        if (value != null) {
            return value;
        }
        return defaultValue;
    }

    /**
	 * Return true if the given service is ready to be used,
         * means initialized and running.
	 *
	 * @param serviceClass
	 * @return isReady
	 */
    public boolean isReady(final Class serviceClass) {
        Service service = serviceCache.get(serviceClass);
        return (service != null && service.isRunning());
    }

    public StructrConf getCurrentConfig() {
        return structrConf;
    }

    public Set<String> getResources() {
        final Set<String> resources = new LinkedHashSet<>();
        for (final Object configurationValue : structrConf.values()) {
            for (final String value : configurationValue.toString().split("[\\s ,;]+")) {
                try {
                    final Class candidate = Class.forName(value.toString());
                    if (!candidate.getName().startsWith("org.structr")) {
                        final String codeLocation = candidate.getProtectionDomain().getCodeSource().getLocation().toString();
                        if (codeLocation.startsWith("file:") && codeLocation.endsWith(".jar") || codeLocation.endsWith(".war")) {
                            resources.add(codeLocation.substring(5));
                        }
                    }
                } catch (Throwable ignore) {
                }
            }
        }
        logger.log(Level.INFO, "Found {0} possible resources: {1}", new Object[] { resources.size(), resources });
        return resources;
    }

    public static StructrConf getBaseConfiguration() {
        if (baseConf == null) {
            baseConf = new StructrConf();
            baseConf.setProperty(CONFIGURATION, JarConfigurationProvider.class.getName());
            baseConf.setProperty(CONFIGURED_SERVICES, "NodeService AgentService CronService SchemaService");
            baseConf.setProperty(NEO4J_SHELL_ENABLED, "true");
            baseConf.setProperty(NEO4J_SHELL_PORT, "1337");
            baseConf.setProperty(JSON_INDENTATION, "true");
            baseConf.setProperty(SUPERUSER_USERNAME, "superadmin");
            baseConf.setProperty(SUPERUSER_PASSWORD, RandomStringUtils.randomAlphanumeric(12));
            baseConf.setProperty(BASE_PATH, "");
            baseConf.setProperty(TMP_PATH, "/tmp");
            baseConf.setProperty(DATABASE_PATH, System.getProperty("user.dir").concat("/db"));
            baseConf.setProperty(FILES_PATH, System.getProperty("user.dir").concat("/files"));
            baseConf.setProperty(LOG_DATABASE_PATH, System.getProperty("user.dir").concat("/logDb.dat"));
            baseConf.setProperty(SMTP_HOST, "localhost");
            baseConf.setProperty(SMTP_PORT, "25");
            baseConf.setProperty(TCP_PORT, "54555");
            baseConf.setProperty(UDP_PORT, "57555");
        }
        return baseConf;
    }

    public static void mergeConfiguration(final StructrConf baseConfig, final StructrConf additionalConfig) {
        baseConfig.putAll(additionalConfig);
        trim(baseConfig);
    }

    private void migrateDatabase() {
        final GraphDatabaseService graphDb = getService(NodeService.class).getGraphDb();
        final SecurityContext superUserContext = SecurityContext.getSuperUserInstance();
        final NodeFactory nodeFactory = new NodeFactory(superUserContext);
        final RelationshipFactory relFactory = new RelationshipFactory(superUserContext);
        final App app = StructrApp.getInstance();
        final StringProperty uuidProperty = new StringProperty("uuid");
        final int txLimit = 2000;
        boolean hasChanges = true;
        int actualNodeCount = 0;
        int actualRelCount = 0;
        logger.log(Level.INFO, "Migration of ID properties from uuid to id requested.");
        while (hasChanges) {
            hasChanges = false;
            try (Tx tx = app.tx(false, false)) {
                final Iterator<Node> allNodes = GlobalGraphOperations.at(graphDb).getAllNodes().iterator();
                while (allNodes.hasNext()) {
                    final Node node = allNodes.next();
                    if (node.hasProperty("uuid") && node.getProperty("uuid") instanceof String && !node.hasProperty("id")) {
                        try {
                            final NodeInterface nodeInterface = nodeFactory.instantiate(node);
                            final String uuid = nodeInterface.getProperty(uuidProperty);
                            if (uuid != null) {
                                nodeInterface.setProperty(GraphObject.id, uuid);
                                nodeInterface.removeProperty(uuidProperty);
                                actualNodeCount++;
                                hasChanges = true;
                            }
                        } catch (Throwable t) {
                            t.printStackTrace();
                        }
                    }
                    if (hasChanges && (actualNodeCount % txLimit) == 0) {
                        break;
                    }
                }
                tx.success();
            } catch (Throwable t) {
                t.printStackTrace();
            }
            logger.log(Level.INFO, "Migrated {0} nodes so far.", actualNodeCount);
        }
        logger.log(Level.INFO, "Migrated {0} nodes to new ID property.", actualNodeCount);
        hasChanges = true;
        while (hasChanges) {
            hasChanges = false;
            try (Tx tx = app.tx(false, false)) {
                final Iterator<Relationship> allRels = GlobalGraphOperations.at(graphDb).getAllRelationships().iterator();
                while (allRels.hasNext()) {
                    final Relationship rel = allRels.next();
                    if (rel.hasProperty("uuid") && rel.getProperty("uuid") instanceof String && !rel.hasProperty("id")) {
                        try {
                            final RelationshipInterface relInterface = relFactory.instantiate(rel);
                            final String uuid = relInterface.getProperty(uuidProperty);
                            if (uuid != null) {
                                relInterface.setProperty(GraphObject.id, uuid);
                                relInterface.removeProperty(uuidProperty);
                                actualRelCount++;
                                hasChanges = true;
                            }
                        } catch (Throwable t) {
                            t.printStackTrace();
                        }
                    }
                    if (hasChanges && (actualRelCount % txLimit) == 0) {
                        break;
                    }
                }
                tx.success();
            } catch (Throwable t) {
                t.printStackTrace();
            }
            logger.log(Level.INFO, "Migrated {0} relationships so far.", actualRelCount);
        }
        logger.log(Level.INFO, "Migrated {0} relationships to new ID property.", actualRelCount);
    }

    public static String trim(final String value) {
        return StringUtils.trim(value);
    }

    public static void trim(StructrConf properties) {
        for (Object k : properties.keySet()) {
            properties.put(k, trim((String) properties.get(k)));
        }
    }

    /**
	 * Tries to parse the given String to an int value, returning
	 * defaultValue on error.
	 *
	 * @param value the source String to parse
	 * @param defaultValue the default value that will be returned when parsing fails
	 * @return the parsed value or the given default value when parsing fails
	 */
    public static int parseInt(String value, int defaultValue) {
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ignore) {
        }
        return defaultValue;
    }

    public static boolean parseBoolean(Object source, boolean defaultValue) {
        try {
            return Boolean.parseBoolean(source.toString());
        } catch (Throwable ignore) {
        }
        return defaultValue;
    }

    public static int getGlobalSessionTimeout() {
        if (globalSessionTimeout == -1) {
            globalSessionTimeout = parseInt(Services.getInstance().getConfigurationValue(APPLICATION_SESSION_TIMEOUT, "1800"), 1800);
        }
        return globalSessionTimeout;
    }
}
