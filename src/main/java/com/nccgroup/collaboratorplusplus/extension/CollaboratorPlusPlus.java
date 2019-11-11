package com.nccgroup.collaboratorplusplus.extension;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import com.nccgroup.collaboratorplusplus.extension.ui.ExtensionUI;
import com.nccgroup.collaboratorplusplus.utilities.LogManager;
import org.apache.http.HttpHost;
import org.apache.http.impl.bootstrap.HttpServer;

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
    private ContextManager contextManager;
    private Preferences preferences;
    private ArrayList<IProxyServiceListener> proxyServiceListeners;

    private ExtensionUI ui;
    private BurpTabController burpTabController;

    private HttpServer oldServer;

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
        this.contextManager = new ContextManager(this);
        logManager.setLogLevel(this.preferences.getSetting(PREF_LOG_LEVEL));

        //Clean up proxy service on startup failure and color tab when running/stopped
        this.addProxyServiceListener(new ProxyServiceAdapter() {

            @Override
            public void onStartupSuccess(String message) {
                burpTabController.setTabColor(Color.GREEN);
                oldServer = proxyService.getServer();
            }

            @Override
            public void onStartupFail(String message) {
                shutdownProxyService();
            }

            @Override
            public void onShutdown() {
                burpTabController.setTabColor(Color.RED);
            }
        });

        //Color tab orange if errors, green if working correctly.
        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingResponseReceived(String collaboratorServer, String contextIdentifier, ArrayList<Interaction> interactions) {
                burpTabController.setTabColor(Color.GREEN);
            }

            @Override
            public void onPollingFailure(String collaboratorServer, String contextIdentifier, String error) {
                burpTabController.setTabColor(Color.ORANGE);
            }
        });


        SwingUtilities.invokeLater(() -> {
            CollaboratorPlusPlus.callbacks.registerExtensionStateListener(this);

            //Create UI and ask burp to add its tab.
            this.ui = new ExtensionUI(this);
            CollaboratorPlusPlus.callbacks.addSuiteTab(this.ui);
            //Use the ui component to get the parent tabbed pane.
            JTabbedPane burpTabbedPane = this.ui.getBurpTabbedPane();
            //Setup tab controller using the main tabbed panel we found.
            this.burpTabController = new BurpTabController(burpTabbedPane, this.ui.getUiComponent(), null, null);

            //Start off the tab as red, until we've started up.
            burpTabController.setTabColor(Color.RED);

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
        proxyService = new ProxyService(contextManager, proxyServiceListeners,
                collaboratorAddress, listenPort, pollingAddress,
                useAuthentication, secret, ignoreCertificateErrors, verifyHostname, proxy);

        if(tryCloseCollaboratorWindows() && getCollaboratorFrames().size() > 0){
            //User accepted request to close collaborator windows.
            JOptionPane.showMessageDialog(this.ui.getUiComponent(),
                    "A Collaborator client window was not closed. Its interactions will not be captured.",
                    "Collaborator client warning", JOptionPane.WARNING_MESSAGE);
        }

        proxyService.start();
    }

    private ArrayList<Frame> getCollaboratorFrames(){
        Frame[] frames = Frame.getFrames();
        ArrayList<Frame> collaboratorFrames = new ArrayList<>();
        for (Frame frame : frames) {
            if(frame.getTitle().equalsIgnoreCase("Burp Collaborator client") && frame.isShowing()){
                collaboratorFrames.add(frame);
            }
        }
        return collaboratorFrames;
    }

    /**
     * Check for any open collaborator windows and ask user if it's okay to close them and proceed.
     * @return boolean True if its okay to proceed.
     */
    public boolean tryCloseCollaboratorWindows(){
        ArrayList<Frame> collaboratorFrames = getCollaboratorFrames();
        if(collaboratorFrames.size() == 0) return true;

        if(JOptionPane.showConfirmDialog(ui.getUiComponent(), "Collaborator++ has detected open collaborator client windows.\n" +
                        "It is recommended that existing Collaborator clients are closed and reopened once Collaborator++ is running, or it will not be able to detect these interactions.\n\n" +
                        "Close them now?",
                "Existing Collaborator Windows", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE) == JOptionPane.NO_OPTION){
            return false;
        }

        for (Frame collaboratorFrame : collaboratorFrames) {
            //Cannot simply close the windows. We must trigger the close event to make sure
            //Burp shuts down the scheduled polling event.
            collaboratorFrame.dispatchEvent(new WindowEvent(collaboratorFrame, WindowEvent.WINDOW_CLOSING));
        }

        return true;
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

    public ContextManager getContextManager() {
        return this.contextManager;
    }
}
