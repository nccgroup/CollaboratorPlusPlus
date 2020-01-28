package com.nccgroup.collaboratorplusplus.extension;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import com.nccgroup.collaboratorplusplus.extension.ui.ExtensionUI;
import org.apache.http.HttpHost;
import org.apache.http.impl.bootstrap.HttpServer;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.AppenderRef;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;

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
    public static Logger logger;
    private ProxyService proxyService;
    private ContextManager contextManager;
    private Preferences preferences;
    private ArrayList<IProxyServiceListener> proxyServiceListeners;

    private ExtensionUI ui;
    private BurpTabController burpTabController;

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
        proxyServiceListeners = new ArrayList<>();

        //Setup preferences
        DefaultGsonProvider gsonProvider = new DefaultGsonProvider();
        this.preferences = new CollaboratorPreferenceFactory(gsonProvider, callbacks).buildPreferences();
        this.contextManager = new ContextManager(this);

        //Load log level from preferences
        Level logLevel = preferences.getSetting(PREF_LOG_LEVEL);

        //Setup logger
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        Configuration config = context.getConfiguration();
        PatternLayout logLayout = PatternLayout.newBuilder()
                .withConfiguration(config)
                .withPattern("[%-5level] %d{yyyy-MM-dd HH:mm:ss} %msg%n")
                .build();
        JTextAreaAppender textAreaAppender = JTextAreaAppender.createAppender("JTextAreaAppender", 500,
                false, logLayout, null);
        textAreaAppender.start();
        config.addAppender(textAreaAppender);

        AppenderRef[] appenderRefs = new AppenderRef[]{
                AppenderRef.createAppenderRef("JTextAreaAppender", null, null)
        };
        LoggerConfig loggerConfig = LoggerConfig.createLogger(false, logLevel, "CollaboratorPlusPlus", "true",
                appenderRefs, null, config, null);
        loggerConfig.addAppender(textAreaAppender, null, null);
        config.addLogger(EXTENSION_NAME, loggerConfig);
        context.updateLoggers();

        logger = LogManager.getLogger(EXTENSION_NAME);

        //Clean up proxy service on startup failure and color tab when running/stopped
        this.addProxyServiceListener(new ProxyServiceAdapter() {

            @Override
            public void onStartupSuccess(String message) {
                logger.info("Local authentication proxy started!");
                SwingUtilities.invokeLater(() -> burpTabController.setTabColor(new Color(60, 146, 38)));
            }

            @Override
            public void onStartupFail(String message) {
                logger.info("Failed to start the local authentication proxy, Reason: " + message);
                shutdownProxyService();
            }

            @Override
            public void onShutdown() {
                SwingUtilities.invokeLater(() -> {
                    if(UIManager.getLookAndFeel().getName().equalsIgnoreCase("darcula")) {
                        burpTabController.setTabColor(new Color(212, 60, 55));
                    }else{
                        burpTabController.setTabColor(new Color(220, 10, 19));
                    }
                });
            }
        });

        //Color tab orange if errors, green if working correctly.
        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingResponseReceived(CollaboratorContext collaboratorContext, ArrayList<Interaction> interactions) {
                SwingUtilities.invokeLater(() -> burpTabController.setTabColor(new Color(60, 146, 38)));
            }

            @Override
            public void onPollingFailure(CollaboratorContext collaboratorContext, String error) {
                SwingUtilities.invokeLater(() -> burpTabController.setTabColor(Color.ORANGE));
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
            if(UIManager.getLookAndFeel().getName().equalsIgnoreCase("darcula")) {
                burpTabController.setTabColor(new Color(212, 60, 55));
            }else{
                burpTabController.setTabColor(new Color(220, 10, 19));
            }

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
            logger.info("Polling location was not configured. Defaulting to the Collaborator address.");
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
        logger.info("Proxy Service Stopped...");
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

    public ContextManager getContextManager() {
        return this.contextManager;
    }
}
