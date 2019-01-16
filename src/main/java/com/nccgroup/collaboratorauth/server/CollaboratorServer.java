package com.nccgroup.collaboratorauth.server;

import nu.studer.java.util.OrderedProperties;
import org.apache.http.ExceptionLogger;
import org.apache.http.impl.NoConnectionReuseStrategy;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.http.impl.bootstrap.ServerBootstrap;
import org.apache.http.ssl.SSLContexts;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetAddress;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

public class CollaboratorServer {

    private static final String COLLABORATOR_SERVER_ADDRESS = "collaborator_server_address";
    private static final String COLLABORATOR_SERVER_PORT = "collaborator_server_port";
    private static final String COLLABORATOR_SERVER_ISHTTPS = "collaborator_server_ishttps";
    private static final String SECRET = "secret";
    private static final String LISTEN_PORT = "listen_port";
    private static final String LISTEN_ADDRESS = "listen_address";
    private static final String LISTEN_SSL = "listen_ssl";
    private static final String KEYSTORE_FILE = "keystore_file";
    private static final String KEYSTORE_PASSWORD = "keystore_password";
    private static final String KEYSTORE_KEY_PASSWORD = "keystore_key_password";

    private HttpServer server;
    private Integer listenPort;

    private CollaboratorServer(Properties properties) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyManagementException {
        String actualAddress = properties.getProperty(COLLABORATOR_SERVER_ADDRESS);
        Integer actualPort = Integer.parseInt(properties.getProperty(COLLABORATOR_SERVER_PORT));
        boolean actualIsHttps = Boolean.parseBoolean(properties.getProperty(COLLABORATOR_SERVER_ISHTTPS));

        listenPort = Integer.parseInt(properties.getProperty(LISTEN_PORT));
        InetAddress listenAddress = InetAddress.getByName(properties.getProperty(LISTEN_ADDRESS));
        boolean listenSSL = Boolean.parseBoolean(properties.getProperty(LISTEN_SSL));

        String secret = properties.getProperty(SECRET);

        ServerBootstrap serverBootstrap = ServerBootstrap.bootstrap()
                .setConnectionReuseStrategy(new NoConnectionReuseStrategy())
                .setListenerPort(listenPort)
                .setLocalAddress(listenAddress)
                .registerHandler("*", new HttpHandler(actualAddress, actualPort, actualIsHttps, secret));

        if(listenSSL){
            File keystoreFile = new File(properties.getProperty(KEYSTORE_FILE));
            String storePassword = properties.getProperty(KEYSTORE_PASSWORD);
            String keyPassword = properties.getProperty(KEYSTORE_KEY_PASSWORD);
            SSLContext sslContext = createSSLContext(keystoreFile, storePassword, keyPassword);
            serverBootstrap.setSslContext(sslContext);
        }

        serverBootstrap.setExceptionLogger(ex -> {System.out.println(ex.getMessage()); ex.printStackTrace();});

        server = serverBootstrap.create();
    }

    public void start() throws IOException {
        if(server != null) {
            server.start();
            System.out.println("Server started. Listening for poll requests on port " + listenPort + "...");
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                server.shutdown(5, TimeUnit.SECONDS);
            }));
        }
    }

    private SSLContext createSSLContext(final File keyStoreFile, final String storePassword, final String keyPassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException, KeyManagementException {
        return SSLContexts.custom()
                .loadKeyMaterial(keyStoreFile, storePassword.toCharArray(), keyPassword.toCharArray())
                .build();
    }
    public static void main(String[] args) throws IOException {
        OrderedProperties properties = getDefaultProperties();
        if(args.length == 0){
            //Create default properties file
            File defaultsFile = new File("CollaboratorServer.properties");
            if(defaultsFile.exists()){
                System.err.println("Could not create the defaults file. File exists.");
                System.err.println("Start the server with `java -jar CollaboratorAuth.jar " + defaultsFile.getName() + "`" +
                        " or remove the file to allow it to be populated with the defaults");
                return;
            }
            FileOutputStream outputStream = new FileOutputStream(defaultsFile);
            properties.store(outputStream, "MAKE SURE THE SECRET IS CHANGED TO SOMETHING MORE SECURE!");
            System.out.println("Default config written to " + defaultsFile.getName());
            System.out.println("Edit the config (especially the secret!)");
            System.out.println("Then start the server with `java -jar CollaboratorAuth.jar " + defaultsFile.getName() + "`");
            return;
        }else{
            File configFile = new File(args[0]);
            if(!configFile.exists()){
                System.err.println("Config file does not exist. Run the jar without arguments to generate the default config.");
                return;
            }else{
                FileInputStream inputStream = new FileInputStream(configFile);
                try {
                    properties.load(inputStream);
                }finally {
                    inputStream.close();
                }
            }
        }

        try {
            CollaboratorServer server = new CollaboratorServer(properties.toJdkProperties());
            server.start();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static OrderedProperties getDefaultProperties(){
        OrderedProperties defaultProperties = new OrderedProperties();
        defaultProperties.setProperty(COLLABORATOR_SERVER_ADDRESS, "127.0.0.1");
        defaultProperties.setProperty(COLLABORATOR_SERVER_PORT, "80");
        defaultProperties.setProperty(LISTEN_PORT, "5050");
        defaultProperties.setProperty(LISTEN_ADDRESS, "0.0.0.0");
        defaultProperties.setProperty(LISTEN_SSL, "false");
        defaultProperties.setProperty(KEYSTORE_FILE, "/path/to/java/keystore");
        defaultProperties.setProperty(KEYSTORE_PASSWORD, "KEYSTOREPASSWORD");
        defaultProperties.setProperty(KEYSTORE_KEY_PASSWORD, "KEYSTOREPASSWORD_FOR_KEYS");
        defaultProperties.setProperty(SECRET, "CHANGE_ME");

        return defaultProperties;
    }
}
