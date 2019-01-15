package com.nccgroup.collaboratorauth.extension;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorauth.extension.ui.ConfigUI;

import javax.swing.*;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.net.URISyntaxException;

public class CollaboratorAuthenticator implements IBurpExtender, IExtensionStateListener {

    public static final String EXTENSION_NAME = "CollaboratorAuth";
    public static final String PREF_REMOTE_ADDRESS = "remoteAddress";
    public static final String PREF_REMOTE_PORT = "remotePort";
    public static final String PREF_REMOTE_SSL_ENABLED = "remoteSSLEnabled";
    public static final String PREF_LOCAL_PORT = "localPort";
    public static final String PREF_SECRET = "sharedSecret";

    //Vars
    public static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ProxyService proxyService;
    private Preferences preferences;

    //UI
    private JPanel ui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        CollaboratorAuthenticator.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        //Setup preferences
        this.preferences = new Preferences(new DefaultGsonProvider(), callbacks);
        this.preferences.addSetting(PREF_REMOTE_ADDRESS, String.class, "your.collaborator.authenticator.server");
        this.preferences.addSetting(PREF_REMOTE_PORT, Integer.class, 5050);
        this.preferences.addSetting(PREF_REMOTE_SSL_ENABLED, Boolean.class, true);

        this.preferences.addSetting(PREF_LOCAL_PORT, Integer.class, 32541);
        this.preferences.addSetting(PREF_SECRET, String.class, "Your Secret String");

        SwingUtilities.invokeLater(() -> {
            CollaboratorAuthenticator.callbacks.addSuiteTab(new ConfigUI(this));
            CollaboratorAuthenticator.callbacks.registerExtensionStateListener(this);
        });
    }

    public void startCollaboratorProxy() throws IOException, URISyntaxException {
        boolean ssl = (boolean) this.preferences.getSetting(PREF_REMOTE_SSL_ENABLED);


        URI destination = new URI(ssl ? "https" : "http", null,
                (String) this.preferences.getSetting(PREF_REMOTE_ADDRESS), (Integer) this.preferences.getSetting(PREF_REMOTE_PORT),
                null, null, null);

        startCollaboratorProxy((Integer) this.preferences.getSetting(PREF_LOCAL_PORT), destination,
                (String) this.preferences.getSetting(PREF_SECRET));
    }

    public void startCollaboratorProxy(Integer listenPort, URI destinationURI, String secret) throws IOException {
        //Start the proxy service listening at the given location
        if(proxyService != null) proxyService.stop();

        proxyService = new ProxyService(this, listenPort, true, true, destinationURI, secret);

        proxyService.start();

//        System.out.println("Polling Listener Started on Port: " + listenPort);
        callbacks.printOutput("Polling Listener Started on Port: " + listenPort);
        callbacks.loadConfigFromJson(buildConfig(listenPort));
    }

    public void stopCollaboratorProxy(){
        if(proxyService != null) {
            proxyService.stop();
            proxyService = null;
            //System.out.println("Polling Listener Stopped...");
            callbacks.printOutput("Polling Listener Stopped...");
        }
    }

    public ProxyService getProxyService() {
        return proxyService;
    }

    private String buildConfig(int listenPort){
        return "{\"project_options\": {\"misc\": {\"collaborator_server\": " +
                "{\"polling_location\": \"" + Inet4Address.getLoopbackAddress().getHostName() + ":" + listenPort + "\"," +
                "\"poll_over_unencrypted_http\": \"true\"" +
                "}}}}";
    }

    @Override
    public void extensionUnloaded() {
        stopCollaboratorProxy();
    }

    public Preferences getPreferences() {
        return this.preferences;
    }
}
