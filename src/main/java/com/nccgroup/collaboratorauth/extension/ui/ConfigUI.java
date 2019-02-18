package com.nccgroup.collaboratorauth.extension.ui;

import burp.ITab;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;
import com.nccgroup.collaboratorauth.extension.ProxyServiceListener;
import org.apache.http.impl.bootstrap.HttpServer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.concurrent.TimeUnit;

public class ConfigUI implements ITab {

    private final CollaboratorAuthenticator extension;
    private final JPanel mainPanel;
    private JToggleButton startStopButton;
    private JSpinner localPortSpinner;
    private JSpinner remotePortSpinner;
    private JTextField remoteAddressField;
    private JTextField collaboratorLocationField;
    private JCheckBox sslEnabledCheckbox;
    private JTextArea secretArea;
    private JLabel statusLabel;

    private boolean serverStarting = false;

    public ConfigUI(CollaboratorAuthenticator extension){
        this.extension = extension;
        this.mainPanel = buildMainPanel();
    }

    public JPanel buildMainPanel(){

//                CollaboratorAuthenticator.callbacks.createBurpCollaboratorClientContext().fetchAllCollaboratorInteractions();
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent componentEvent) {
                mainPanel.revalidate();
                mainPanel.repaint();
                SwingUtilities.getWindowAncestor(mainPanel).pack();
            }
        });

        PanelBuilder panelBuilder = new PanelBuilder(extension.getPreferences());
        PanelBuilder.ComponentGroup configGroup = panelBuilder.createComponentGroup("Configuration");
        localPortSpinner = (JSpinner) configGroup.addSetting(CollaboratorAuthenticator.PREF_LOCAL_PORT, "Local Port");
        ((SpinnerNumberModel) localPortSpinner.getModel()).setMinimum(0);
        ((SpinnerNumberModel) localPortSpinner.getModel()).setMaximum(65535);
        localPortSpinner.setEditor(new JSpinner.NumberEditor(localPortSpinner, "#"));
        collaboratorLocationField = (JTextField) configGroup.addSetting(CollaboratorAuthenticator.PREF_COLLABORATOR_ADDRESS, "Collaborator Location");
        remoteAddressField = (JTextField) configGroup.addSetting(CollaboratorAuthenticator.PREF_POLLING_ADDRESS, "Collaborator Polling Location");
        remotePortSpinner = (JSpinner) configGroup.addSetting(CollaboratorAuthenticator.PREF_POLLING_PORT, "Collaborator Auth Port");
        ((SpinnerNumberModel) remotePortSpinner.getModel()).setMinimum(0);
        ((SpinnerNumberModel) remotePortSpinner.getModel()).setMaximum(65535);
        remotePortSpinner.setEditor(new JSpinner.NumberEditor(remotePortSpinner, "#"));
        sslEnabledCheckbox = (JCheckBox) configGroup.addSetting(CollaboratorAuthenticator.PREF_REMOTE_SSL_ENABLED, "Use SSL?");

        secretArea = configGroup.addTextAreaSetting(CollaboratorAuthenticator.PREF_SECRET);
        secretArea.setLineWrap(true);
        secretArea.setRows(30);
        JScrollPane secretScrollPane = new JScrollPane(secretArea);
        secretScrollPane.setBorder(BorderFactory.createTitledBorder("Shared Secret"));
//        secretScrollPanePanel.add(new JScrollPane(secretArea), BorderLayout.CENTER);

        //Control Panel
        PanelBuilder.ComponentGroup controlGroup = panelBuilder.createComponentGroup("Control");
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

        try {
            return panelBuilder.build(new JComponent[][]{
                    new JComponent[]{null, configGroup, controlGroup, null},
                    new JComponent[]{null, secretScrollPane, secretScrollPane, null},
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
        localPortSpinner.setEnabled(false);
        collaboratorLocationField.setEnabled(false);
        remoteAddressField.setEnabled(false);
        remotePortSpinner.setEnabled(false);
        sslEnabledCheckbox.setEnabled(false);
        secretArea.setEnabled(false);

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
            new Thread(() ->{
                CollaboratorAuthenticator.callbacks.createBurpCollaboratorClientContext().fetchAllCollaboratorInteractions();
            }).start();

        }catch (Exception e){
            onServerStartFailure("Could not start local server: " + e.getMessage());
        }
    }

    private void onServerStartFailure(String message){
        serverStarting = false;
        SwingUtilities.invokeLater(() -> {
            JOptionPane.showMessageDialog(null, message, "Error", JOptionPane.OK_OPTION);
        });

        startStopButton.setText("Start");
        startStopButton.setSelected(false);
        startStopButton.setEnabled(true);

        //Enable all other controls
        localPortSpinner.setEnabled(true);
        collaboratorLocationField.setEnabled(true);
        remoteAddressField.setEnabled(true);
        remotePortSpinner.setEnabled(true);
        sslEnabledCheckbox.setEnabled(true);
        secretArea.setEnabled(true);

        statusLabel.setText("Status: Not Running");

        if(extension.getProxyService() != null)
            extension.stopCollaboratorProxy();
    }

    private void onServerStartSuccess(String message){
        startStopButton.setText("Stop");
        statusLabel.setText("Status: Listening on port " + localPortSpinner.getValue());

        //Disable all other controls
        localPortSpinner.setEnabled(false);
        collaboratorLocationField.setEnabled(false);
        remoteAddressField.setEnabled(false);
        remotePortSpinner.setEnabled(false);
        sslEnabledCheckbox.setEnabled(false);
        secretArea.setEnabled(false);

        startStopButton.setEnabled(true);
    }

    private void stopServer(){
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
                localPortSpinner.setEnabled(true);
                collaboratorLocationField.setEnabled(true);
                remoteAddressField.setEnabled(true);
                remotePortSpinner.setEnabled(true);
                sslEnabledCheckbox.setEnabled(true);
                secretArea.setEnabled(true);

            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        startStopButton.setEnabled(true);
        startStopButton.setText("Start");
    }

    @Override
    public String getTabCaption() {
        return CollaboratorAuthenticator.EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
