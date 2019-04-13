package com.nccgroup.collaboratorauth.extension.ui;

import burp.ITab;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;
import com.nccgroup.collaboratorauth.extension.LogListener;
import com.nccgroup.collaboratorauth.extension.ProxyServiceListener;
import com.nccgroup.collaboratorauth.extension.Utilities;
import org.apache.http.impl.bootstrap.HttpServer;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.util.concurrent.TimeUnit;

import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.callbacks;
import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.logController;
import static com.nccgroup.collaboratorauth.extension.Globals.*;

public class ConfigUI implements ITab, LogListener {

    private final CollaboratorAuthenticator extension;
    private final JPanel mainPanel;
    private JToggleButton startStopButton;
    private JSpinner localPortSpinner;
    private JSpinner remotePortSpinner;
    private JTextField remoteAddressField;
    private JTextField collaboratorLocationField;
    private JCheckBox sslEnabledCheckbox;
    private JCheckBox blockPublicCollaborator;
    private JTextArea secretArea;
    private JLabel statusLabel;
    private JTextArea logArea;

    private boolean serverStarting = false;

    public ConfigUI(CollaboratorAuthenticator extension){
        this.extension = extension;
        CollaboratorAuthenticator.logController.addLogListener(this);
        this.mainPanel = buildMainPanel();
    }

    public JPanel buildMainPanel(){

        PanelBuilder panelBuilder = new PanelBuilder(extension.getPreferences());
        ComponentGroup configGroup = panelBuilder.createComponentGroup("Configuration");
        localPortSpinner = (JSpinner) configGroup.addPreferenceComponent(PREF_LOCAL_PORT, "Local Port");
        ((SpinnerNumberModel) localPortSpinner.getModel()).setMinimum(0);
        ((SpinnerNumberModel) localPortSpinner.getModel()).setMaximum(65535);
        localPortSpinner.setEditor(new JSpinner.NumberEditor(localPortSpinner, "#"));
        collaboratorLocationField = (JTextField) configGroup.addPreferenceComponent(PREF_COLLABORATOR_ADDRESS, "Collaborator Location");
        remoteAddressField = (JTextField) configGroup.addPreferenceComponent(PREF_POLLING_ADDRESS, "Collaborator Polling Location");
        remotePortSpinner = (JSpinner) configGroup.addPreferenceComponent(PREF_POLLING_PORT, "Collaborator Auth Port");
        ((SpinnerNumberModel) remotePortSpinner.getModel()).setMinimum(0);
        ((SpinnerNumberModel) remotePortSpinner.getModel()).setMaximum(65535);
        remotePortSpinner.setEditor(new JSpinner.NumberEditor(remotePortSpinner, "#"));
        sslEnabledCheckbox = (JCheckBox) configGroup.addPreferenceComponent(PREF_REMOTE_SSL_ENABLED, "Use SSL?");
        blockPublicCollaborator = (JCheckBox) configGroup.addPreferenceComponent(PREF_BLOCK_PUBLIC_COLLABORATOR, "Block Public Collaborator Server?");
        blockPublicCollaborator.addActionListener(actionEvent -> {
            if(blockPublicCollaborator.isSelected()) Utilities.blockPublicCollaborator();
            else Utilities.unblockPublicCollaborator();
        });


        //Control Panel
        ComponentGroup controlGroup = panelBuilder.createComponentGroup("Control");
        statusLabel = new JLabel("Status: Not Running");
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);
        controlGroup.addComponent(statusLabel);

        startStopButton = controlGroup.addToggleButton("Start", actionEvent -> {
            JToggleButton thisButton = (JToggleButton) actionEvent.getSource();
            SwingUtilities.invokeLater(() -> {
                if(thisButton.isSelected()){
                    startServer();
                }else{
                    stopServer();
                }
            });
        });

        ComponentGroup secretGroup = panelBuilder.createComponentGroup("Shared Secret");
        secretArea = panelBuilder.createPreferenceTextArea(PREF_SECRET);
        secretArea.setLineWrap(true);
        secretArea.setRows(30);
        secretArea.setColumns(40);
        JScrollPane secretScrollPane = new JScrollPane(secretArea);
        secretScrollPane.setBorder(null);
        secretGroup.addComponent(secretScrollPane);
        secretGroup.setMinimumSize(new Dimension(400, 400));

        ComponentGroup logGroup = panelBuilder.createComponentGroup("Message Log");
        logArea = new JTextArea(30,40);
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setBorder(null);
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(null);
        logGroup.addComponent(logScrollPane);
        JButton clearButton = panelBuilder.createButton("Clear Logs", actionEvent -> {
            logArea.setText("");
        });
        clearButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));
        logGroup.addComponent(clearButton);
        logGroup.setMinimumSize(new Dimension(400, 400));

        try {
            return panelBuilder.build(new JComponent[][]{
                    new JComponent[]{null, configGroup, controlGroup, null},
                    new JComponent[]{null, secretGroup, logGroup, null},
            }, PanelBuilder.Alignment.TOPMIDDLE);
        } catch (Exception e) {
            e.printStackTrace();
            JLabel error = new JLabel("Could not build the panel! :(");
            JPanel panel = new JPanel();
            panel.add(error);
            return panel;
        }
    }

    private void startServer(){
        startStopButton.setText("Starting...");
        startStopButton.setEnabled(false);
        serverStarting = true;

        //Disable all other controls
        enableControls(false);

        try{
            extension.startCollaboratorProxy();

            //Check the authentication
            ProxyServiceListener failListener = new ProxyServiceListener() {
                @Override
                public void onFail(String message) {
                    //Synchronized to stop double error issue.
                    synchronized (this) {
                        if(serverStarting) {
                            onServerStartFailure(message);
                            if (extension.getProxyService() != null) {
                                extension.getProxyService().removeProxyServiceListener(this);
                                extension.stopCollaboratorProxy();
                            }
                        }
                    }
                }

                @Override
                public void onSuccess(String message) {
                    synchronized (this) {
                        onServerStartSuccess(message);
                        if (extension.getProxyService() != null) {
                            extension.getProxyService().removeProxyServiceListener(this);
                        }
                    }
                }
            };

            extension.getProxyService().addProxyServiceListener(failListener);

            //Wait a 500ms for the server to start,
            //then trigger a polling request to test authentication...
            new Thread(() -> callbacks.createBurpCollaboratorClientContext().fetchAllCollaboratorInteractions()).start();

        }catch (Exception e){
            onServerStartFailure("Could not start local server: " + e.getMessage());
        }
    }

    private void onServerStartFailure(String message){
        logController.logError("Could not start local authentication proxy: " + message);
        serverStarting = false;

        startStopButton.setText("Start");
        startStopButton.setSelected(false);
        startStopButton.setEnabled(true);

        //Enable all other controls
        enableControls(true);

        statusLabel.setText("Status: Not Running");

        if(extension.getProxyService() != null)
            extension.stopCollaboratorProxy();
    }

    private void onServerStartSuccess(String message){
        logController.logInfo("Local authentication proxy started!");
        startStopButton.setText("Stop");
        statusLabel.setText("Status: Listening on port " + localPortSpinner.getValue());

        //Disable all other controls
        enableControls(false);

        startStopButton.setEnabled(true);
    }

    private void stopServer(){
        logController.logInfo("Stopping local authentication proxy...");
        startStopButton.setText("Stopping...");
        startStopButton.setEnabled(false);
        if(extension.getProxyService() != null) {
            try {
                extension.stopCollaboratorProxy();
                if(extension.getProxyService() != null) {
                    HttpServer proxyserver = extension.getProxyService().getServer();
                    proxyserver.awaitTermination(10, TimeUnit.SECONDS);
                }
                statusLabel.setText("Status: Not Running");

                //Reenable other controls
                //Disable all other controls
                enableControls(true);

            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        startStopButton.setEnabled(true);
        startStopButton.setText("Start");
    }

    private void enableControls(boolean enabled){
        localPortSpinner.setEnabled(enabled);
        collaboratorLocationField.setEnabled(enabled);
        remoteAddressField.setEnabled(enabled);
        remotePortSpinner.setEnabled(enabled);
        sslEnabledCheckbox.setEnabled(enabled);
        blockPublicCollaborator.setEnabled(enabled);
        secretArea.setEnabled(enabled);
    }
    
    @Override
    public void onInfo(String message) {
        logArea.append("INFO: " + message + "\n");
    }

    @Override
    public void onError(String message) {
        logArea.append("ERROR: " + message + "\n");
    }

    @Override
    public void onDebug(String message) {
        logArea.append("DEBUG: " + message + "\n");
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
