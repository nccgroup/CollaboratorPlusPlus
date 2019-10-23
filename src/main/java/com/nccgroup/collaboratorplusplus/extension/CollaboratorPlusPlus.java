package com.nccgroup.collaboratorplusplus.extension;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContextManager;
import com.nccgroup.collaboratorplusplus.extension.ui.ExtensionUI;
import com.nccgroup.collaboratorplusplus.utilities.LogManager;
import org.apache.http.HttpHost;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowEvent;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;

import static com.nccgroup.collaboratorplusplus.extension.Globals.*;

public class CollaboratorPlusPlus implements IBurpExtender, IExtensionStateListener {

    //Vars
    public static IBurpExtenderCallbacks callbacks;
    public static LogManager logManager;
    private ProxyService proxyService;
    private CollaboratorContextManager collaboratorContextManager;
    private Preferences preferences;
    private ArrayList<IProxyServiceListener> proxyServiceListeners;

    private ExtensionUI ui;

    public CollaboratorPlusPlus(){
        //Fix Darcula's issue with JSpinner UI.
        try {
            Class spinnerUI = Class.forName("com.bulenkov.darcula.ui.DarculaSpinnerUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSpinnerUI", spinnerUI);
            Class sliderUI = Class.forName("com.bulenkov.darcula.ui.DarculaSliderUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSliderUI", sliderUI);
        } catch (ClassNotFoundException ignored) {
            //Darcula is not installed.
        }
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        CollaboratorPlusPlus.callbacks = callbacks;
        CollaboratorPlusPlus.logManager = new LogManager();
        proxyServiceListeners = new ArrayList<>();

        //Setup preferences
        DefaultGsonProvider gsonProvider = new DefaultGsonProvider();
        this.preferences = new CollaboratorPreferenceFactory(gsonProvider, callbacks).buildPreferences();

        this.collaboratorContextManager = new CollaboratorContextManager(this);

        logManager.setLogLevel(this.preferences.getSetting(PREF_LOG_LEVEL));

        //Clean up proxy service on startup failure.
        this.addProxyServiceListener(new ProxyServiceAdapter() {
            @Override
            public void onStartupFail(String message) {
                shutdownProxyService();
            }
        });

        SwingUtilities.invokeLater(() -> {
            this.ui = new ExtensionUI(this);
            CollaboratorPlusPlus.callbacks.addSuiteTab(this.ui);
            CollaboratorPlusPlus.callbacks.registerExtensionStateListener(this);
            this.ui.addMenuItemsToBurp();

            if(this.preferences.getSetting(PREF_AUTO_START)){
                new Thread(() -> {
                    try {
                        Thread.sleep(500);
                        startCollaboratorProxy();
                    } catch (Exception ignored) {}
                }).start();
            }
        });

        if(this.preferences.getSetting(PREF_BLOCK_PUBLIC_COLLABORATOR)){
            Utilities.blockPublicCollaborator();
        }
    }

    public void startCollaboratorProxy() throws URISyntaxException {
        if(isProxyServiceRunning()) throw new IllegalStateException("The proxy service is already running.");

        for (IProxyServiceListener listener : proxyServiceListeners) {
            try {
                listener.beforeStartup();
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }

        String collaboratorAddress = preferences.getSetting(PREF_COLLABORATOR_ADDRESS);
        if(preferences.getSetting(PREF_POLLING_ADDRESS).equals("")){
            logManager.logInfo("Polling location was not configured. Defaulting to the Collaborator address.");
            preferences.setSetting(PREF_POLLING_ADDRESS, collaboratorAddress);
        }

        boolean ssl = this.preferences.getSetting(PREF_REMOTE_SSL_ENABLED);

        URI pollingAddress = new URI(ssl ? "https" : "http", null,
                this.preferences.getSetting(PREF_POLLING_ADDRESS),
                this.preferences.getSetting(PREF_POLLING_PORT), "/", null, null);
        boolean useAuthentication = this.preferences.getSetting(PREF_USE_AUTHENTICATION);
        int listenPort = this.preferences.getSetting(PREF_LOCAL_PORT);
        String secret = ((String) this.preferences.getSetting(PREF_SECRET)).trim();

        boolean ignoreCertificateErrors = this.preferences.getSetting(PREF_IGNORE_CERTIFICATE_ERRORS);
        boolean verifyHostname = this.preferences.getSetting(PREF_SSL_HOSTNAME_VERIFICATION);
        HttpHost proxy = null;
        if(this.preferences.getSetting(PREF_PROXY_REQUESTS_WITH_BURP)){
//            TEMPORARILY DISABLED UNTIL WORKING
//            proxy = Utilities.getBurpProxyHost(pollingAddress.getScheme());
        }

        Utilities.backupCollaboratorConfig(preferences);
        callbacks.loadConfigFromJson(Utilities.buildPollingRedirectionConfig(preferences, listenPort));

        //Build the proxy service with the required values.
        proxyService = new ProxyService(collaboratorContextManager, proxyServiceListeners,
                collaboratorAddress, listenPort, pollingAddress,
                useAuthentication, secret, ignoreCertificateErrors, verifyHostname, proxy);

        proxyService.start();
    }

    public void shutdownProxyService(){
        if(!isProxyServiceRunning()) throw new IllegalStateException("The proxy service is not running.");
        proxyService.stop();
        logManager.logInfo("Proxy Service Stopped...");
        for (IProxyServiceListener proxyServiceListener : proxyServiceListeners) {
            proxyServiceListener.onShutdown();
        }
        Utilities.restoreCollaboratorConfig(preferences);
    }

    public void addProxyServiceListener(IProxyServiceListener listener){
        this.proxyServiceListeners.add(listener);
    }

    public void removeProxyServiceListener(IProxyServiceListener listener){
        this.proxyServiceListeners.remove(listener);
    }

    public boolean isProxyServiceRunning(){
        return proxyService != null && proxyService.getServer() != null;
    }

    public ProxyService getProxyService() {
        return proxyService;
    }

    @Override
    public void extensionUnloaded() {
        try {
            shutdownProxyService();
        }catch (IllegalStateException ignored){}

        if(this.preferences.getSetting(PREF_BLOCK_PUBLIC_COLLABORATOR)){
            Utilities.unblockPublicCollaborator();
        }
    }

    public Preferences getPreferences() {
        return this.preferences;
    }

    public LogManager getLogController() {
        return logManager;
    }

    public CollaboratorContextManager getContextManager() {
        return this.collaboratorContextManager;
    }
}
