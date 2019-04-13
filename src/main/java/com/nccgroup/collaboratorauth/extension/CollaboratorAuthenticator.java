package com.nccgroup.collaboratorauth.extension;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.*;
import com.nccgroup.collaboratorauth.extension.ui.ConfigUI;
import static com.nccgroup.collaboratorauth.extension.Globals.*;

import javax.swing.*;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.URI;
import java.net.URISyntaxException;

public class CollaboratorAuthenticator implements IBurpExtender, IExtensionStateListener {

    //Vars
    public static IBurpExtenderCallbacks callbacks;
    public static LogController logController;
    private ProxyService proxyService;
    private Preferences preferences;

    //UI
    private JPanel ui;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        CollaboratorAuthenticator.callbacks = callbacks;
        CollaboratorAuthenticator.logController = new LogController();

        //Setup preferences
        this.preferences = new Preferences(new DefaultGsonProvider(), callbacks);
        this.preferences.addSetting(PREF_COLLABORATOR_ADDRESS, String.class, "your.private.collaborator.instance");
        this.preferences.addSetting(PREF_POLLING_ADDRESS, String.class, "your.collaborator.authenticator.server");
        this.preferences.addSetting(PREF_POLLING_PORT, Integer.class, 5050);
        this.preferences.addSetting(PREF_REMOTE_SSL_ENABLED, Boolean.class, true);
        this.preferences.addSetting(PREF_LOCAL_PORT, Integer.class, 32541);
        this.preferences.addSetting(PREF_SECRET, String.class, "Your Secret String");
        this.preferences.addSetting(PREF_ORIGINAL_COLLABORATOR_SETTINGS, String.class, "");
        this.preferences.addSetting(PREF_BLOCK_PUBLIC_COLLABORATOR, Boolean.class, true);

        SwingUtilities.invokeLater(() -> {
            CollaboratorAuthenticator.callbacks.addSuiteTab(new ConfigUI(this));
            CollaboratorAuthenticator.callbacks.registerExtensionStateListener(this);
        });

        if((boolean) this.preferences.getSetting(PREF_BLOCK_PUBLIC_COLLABORATOR)){
            Utilities.blockPublicCollaborator();
        }
    }

    public void startCollaboratorProxy() throws IOException, URISyntaxException {
        boolean ssl = (boolean) this.preferences.getSetting(PREF_REMOTE_SSL_ENABLED);


        URI destination = new URI(ssl ? "https" : "http", null,
                (String) this.preferences.getSetting(PREF_POLLING_ADDRESS),
                (Integer) this.preferences.getSetting(PREF_POLLING_PORT), null, null, null);

        startCollaboratorProxy((Integer) this.preferences.getSetting(PREF_LOCAL_PORT), destination,
                (String) this.preferences.getSetting(PREF_SECRET));
    }

    public void startCollaboratorProxy(Integer listenPort, URI destinationURI, String secret) throws IOException {
        //Start the proxy service listening at the given location
        if(proxyService != null) proxyService.stop();

        proxyService = new ProxyService(this, listenPort, true, true, destinationURI, secret);
        proxyService.start();

        saveCollaboratorConfig();
        callbacks.loadConfigFromJson(buildConfig(listenPort));
    }

    public void stopCollaboratorProxy(){
        if(proxyService != null) {
            proxyService.stop();
            proxyService = null;
            //System.out.println("Polling Listener Stopped...");
            logController.logInfo("Polling Listener Stopped...");
        }
        restoreCollaboratorConfig();
    }

    public ProxyService getProxyService() {
        return proxyService;
    }

    private void saveCollaboratorConfig(){
        String config = callbacks.saveConfigAsJson(COLLABORATOR_SERVER_CONFIG_PATH);
        this.preferences.setSetting(PREF_ORIGINAL_COLLABORATOR_SETTINGS, config);
    }

    private void restoreCollaboratorConfig(){
        String config = (String) this.preferences.getSetting(PREF_ORIGINAL_COLLABORATOR_SETTINGS);
        callbacks.loadConfigFromJson(config);
    }

    private String buildConfig(int listenPort){
        return "{\"project_options\": {\"misc\": {\"collaborator_server\": " +
                "{\"location\": \"" + this.preferences.getSetting(PREF_COLLABORATOR_ADDRESS) + "\"," +
                "\"polling_location\": \"" + Inet4Address.getLoopbackAddress().getHostName() + ":" + listenPort + "\"," +
                "\"poll_over_unencrypted_http\": \"true\"," +
                "\"type\": \"private\"" +
                "}}}}";
    }

    @Override
    public void extensionUnloaded() {
        stopCollaboratorProxy();
    }

    public Preferences getPreferences() {
        return this.preferences;
    }

    public LogController getLogController() {
        return logController;
    }
}
