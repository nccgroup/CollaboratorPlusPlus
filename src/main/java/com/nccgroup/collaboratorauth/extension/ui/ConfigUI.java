package com.nccgroup.collaboratorauth.extension.ui;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;
import com.nccgroup.collaboratorauth.extension.LogListener;
import com.nccgroup.collaboratorauth.extension.ProxyServiceListener;
import com.nccgroup.collaboratorauth.extension.Utilities;
import org.apache.http.impl.bootstrap.HttpServer;

import javax.swing.*;
import javax.swing.text.DefaultCaret;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.concurrent.TimeUnit;

import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.callbacks;
import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.logController;
import static com.nccgroup.collaboratorauth.extension.Globals.*;

public class ConfigUI extends JPanel implements LogListener {

    private final CollaboratorAuthenticator extension;
    private JToggleButton startStopButton;
    private JSpinner localPortSpinner;
    private JSpinner remotePortSpinner;
    private JTextField remoteAddressField;
    private JTextField collaboratorLocationField;
    private JCheckBox sslEnabledCheckbox;
    private JCheckBox trustSelfSignedCheckbox;
    private JCheckBox hostnameVerificationCheckbox;
    private JCheckBox blockPublicCollaborator;
    private JTextArea secretArea;
    private JLabel statusLabel;
    private JTextArea logArea;

    private String logLevel;
    private boolean serverStarting;

    public ConfigUI(CollaboratorAuthenticator extension){
        CollaboratorAuthenticator.logController.addLogListener(this);
        this.setLayout(new BorderLayout());
        this.extension = extension;
        JPanel panel = buildMainPanel();
        this.add(panel, BorderLayout.CENTER);
        this.addMouseListener(new MouseAdapter() {

            @Override
            public void mouseReleased(MouseEvent e) {
                if(e.getButton() != MouseEvent.BUTTON3) return;
                ConfigUI.this.removeAll();
                ConfigUI.this.add(buildMainPanel());
                ConfigUI.this.revalidate();
                ConfigUI.this.repaint();
            }
        });
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


        sslEnabledCheckbox = panelBuilder.createPreferenceCheckBox(PREF_REMOTE_SSL_ENABLED, "Use SSL");
        trustSelfSignedCheckbox = panelBuilder.createPreferenceCheckBox(PREF_IGNORE_CERTIFICATE_ERRORS, "Ignore Certificate Errors");
        hostnameVerificationCheckbox = panelBuilder.createPreferenceCheckBox(PREF_SSL_HOSTNAME_VERIFICATION, "Enable SSL Hostname Verification");
        blockPublicCollaborator = panelBuilder.createPreferenceCheckBox(PREF_BLOCK_PUBLIC_COLLABORATOR, "Block Public Collaborator Server");
        blockPublicCollaborator.addActionListener(actionEvent -> {
            if(blockPublicCollaborator.isSelected()) Utilities.blockPublicCollaborator();
            else Utilities.unblockPublicCollaborator();
        });
        sslEnabledCheckbox.addActionListener(actionEvent -> {
            boolean sslEnabled = sslEnabledCheckbox.isSelected();
            trustSelfSignedCheckbox.setEnabled(sslEnabled);
            hostnameVerificationCheckbox.setEnabled(sslEnabled);
        });
        JComponent checkboxComponentsPanel;
        try {
            checkboxComponentsPanel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{sslEnabledCheckbox, trustSelfSignedCheckbox},
                    new JComponent[]{hostnameVerificationCheckbox, blockPublicCollaborator}
            }, new int[][]{
                    new int[]{1, 1},
                    new int[]{1, 1}
            }, Alignment.FILL, 1, 1);
        } catch (Exception e) {
            checkboxComponentsPanel = new JLabel("Could not build checkbox components panel");
        }
        configGroup.addComponent(checkboxComponentsPanel);


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
        JScrollPane secretScrollPane = new JScrollPane(secretArea);
        secretScrollPane.setBorder(null);
        secretGroup.addComponent(secretScrollPane);

        ComponentGroup logGroup = panelBuilder.createComponentGroup("Message Log");
        logArea = new JTextArea();
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setBorder(null);
        logArea.setEditable(false);
        DefaultCaret caret = (DefaultCaret)logArea.getCaret();
        caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createLineBorder(Color.ORANGE));
        logScrollPane.setBorder(null);
        JPanel logLevelPanel = new JPanel(new GridLayout(1,2));
        JComboBox logLevelSelector = new JComboBox(new String[]{"INFO", "DEBUG"});
        this.logLevel = "INFO";
        logLevelSelector.setSelectedItem(this.logLevel);
        logLevelSelector.addActionListener(e -> {
            this.logLevel = (String) logLevelSelector.getSelectedItem();
        });
        logLevelPanel.add(new JLabel("Log Level: "));
        logLevelPanel.add(logLevelSelector);
        JButton clearButton = panelBuilder.createButton("Clear Logs", actionEvent -> logArea.setText(""));
//        clearButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, 20));

        GridBagConstraints logPanelGbc = logGroup.generateNextConstraints();
        logPanelGbc.weighty = 0;
        logGroup.addComponent(logLevelPanel, logPanelGbc);
        logPanelGbc = logGroup.generateNextConstraints();
        logPanelGbc.weighty = 0;
        logGroup.addComponent(new JSeparator(JSeparator.HORIZONTAL), logPanelGbc);
        logGroup.addComponent(logScrollPane, logGroup.generateNextConstraints());
        logPanelGbc = logGroup.generateNextConstraints();
        logPanelGbc.weighty = 0;
        logGroup.addComponent(clearButton, logPanelGbc);

        try {
            return panelBuilder.build(
                new JComponent[][]{
                    new JComponent[]{configGroup, controlGroup},
                    new JComponent[]{secretGroup, logGroup},
                }, new int[][]{
                    new int[]{0, 0},
                    new int[]{1 ,1},
                }, Alignment.TOPMIDDLE, 1, 1);
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
                public void onFail(String reason) {
                    //Synchronized to stop double error issue.
                    synchronized (this) {
                        if(serverStarting) {
                            onServerStartFailure(reason);
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
                        if(serverStarting) {
                            onServerStartSuccess();
                            if (extension.getProxyService() != null) {
                                extension.getProxyService().removeProxyServiceListener(this);
                            }
                        }
                    }
                }
            };

            extension.getProxyService().addProxyServiceListener(failListener);

            //Wait a 500ms for the server to start,
            //then trigger a polling request to test authentication...
            new Thread(() -> {
                try {
                    callbacks.createBurpCollaboratorClientContext().fetchAllCollaboratorInteractions();
                }catch (IllegalStateException e){
                    //Collaborator is disabled?
                    onServerStartFailure(e.getMessage());
                }
            }).start();

        }catch (Exception e){
            onServerStartFailure(e.getMessage());
        }
    }

    private void onServerStartFailure(String reason){
        logController.logInfo("Failed to start the local authentication proxy, " + reason);
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

    private void onServerStartSuccess(){
        serverStarting = false;
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
        trustSelfSignedCheckbox.setEnabled(enabled);
        hostnameVerificationCheckbox.setEnabled(enabled);
        secretArea.setEnabled(enabled);
    }
    
    @Override
    public void onInfo(String message) {
        if(logArea == null) return;
        synchronized (logArea) {
            logArea.append("INFO: " + message + "\n");
        }
    }

    @Override
    public void onError(String message) {
        if(logArea == null) return;
        synchronized (logArea) {
            if (this.logLevel.equalsIgnoreCase("DEBUG"))
                logArea.append("ERROR: " + message + "\n");
        }
    }

    @Override
    public void onDebug(String message) {
        synchronized (logArea) {
            if (this.logLevel.equalsIgnoreCase("DEBUG"))
                logArea.append("DEBUG: " + message + "\n");
        }
    }
}
