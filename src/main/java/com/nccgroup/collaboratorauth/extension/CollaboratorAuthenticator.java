package com.nccgroup.collaboratorauth.extension;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IExtensionStateListener;
import com.nccgroup.collaboratorauth.extension.ui.ConfigUI;

import javax.swing.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

public class CollaboratorAuthenticator implements IBurpExtender, IExtensionStateListener {

    public static final String extensionName = "CollaboratorAuth";

    //Vars
    public static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private ProxyService proxyService;

    //UI
    private JPanel ui;

    public CollaboratorAuthenticator(){

    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        CollaboratorAuthenticator.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        SwingUtilities.invokeLater(() -> {
            CollaboratorAuthenticator.callbacks.addSuiteTab(new ConfigUI(this));
            CollaboratorAuthenticator.callbacks.registerExtensionStateListener(this);

            try {
                startCollaboratorProxy(8081);
            }catch (IOException | NoSuchAlgorithmException e){
                e.printStackTrace();
            }
        });
    }

    public void startCollaboratorProxy(int port) throws IOException, NoSuchAlgorithmException {
        //Start the proxy service listening at the given location
        if(proxyService != null) proxyService.stop();
        try {
            proxyService = new ProxyService(this, port, true, true, new URI("https://127.0.0.1:9090"), "ABC");
        } catch (URISyntaxException e) {
            e.printStackTrace();
            return;
        }
        try {
            proxyService.start();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        System.out.println("Polling Listener Started on Port: " + port);
        callbacks.printOutput("Polling Listener Started on Port: " + port);
        String configToSet = "{\"project_options\": {\"misc\": {\"collaborator_server\": " +
                "{\"polling_location\": \"localhost:" + port + "\"," +
                "\"poll_over_unencrypted_http\": \"true\"" +
                "}}}}";
        callbacks.loadConfigFromJson(configToSet);
    }

    public void stopCollaboratorProxy(){
        if(proxyService != null) {
            proxyService.stop();
            proxyService = null;
            System.out.println("Polling Listener Stopped...");
            callbacks.printOutput("Polling Listener Stopped...");
        }
    }

    @Override
    public void extensionUnloaded() {
        stopCollaboratorProxy();
    }
}
