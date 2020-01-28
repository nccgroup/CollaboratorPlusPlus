package com.nccgroup.collaboratorplusplus.extension.ui;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.nccgroup.collaboratorplusplus.extension.*;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.config.Configurator;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URISyntaxException;

import static com.nccgroup.collaboratorplusplus.extension.Globals.*;

public class ConfigUI extends JPanel implements IProxyServiceListener {

    private final CollaboratorPlusPlus extension;
    private JToggleButton startStopButton;
    private JSpinner localPortSpinner;
    private JSpinner remotePortSpinner;
    private JTextField collaboratorPollingField;
    private JTextField collaboratorLocationField;
    private JCheckBox sslEnabledCheckbox;
    private JCheckBox trustSelfSignedCheckbox;
    private JCheckBox hostnameVerificationCheckbox;
    private JCheckBox blockPublicCollaborator;
    private JCheckBox proxyRequestsWithBurp;
    private JCheckBox enableAuthentication;
    private JTextArea secretArea;
    private JLabel statusLabel;
    private JTextArea logArea;

    public ConfigUI(CollaboratorPlusPlus extension){
        this.setLayout(new BorderLayout());
        this.extension = extension;
        this.extension.addProxyServiceListener(this);
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
        localPortSpinner = configGroup.addPreferenceComponent(PREF_LOCAL_PORT, "Local Port");
        ((SpinnerNumberModel) localPortSpinner.getModel()).setMinimum(0);
        ((SpinnerNumberModel) localPortSpinner.getModel()).setMaximum(65535);
        localPortSpinner.setEditor(new JSpinner.NumberEditor(localPortSpinner, "#"));
        collaboratorLocationField = configGroup.addPreferenceComponent(PREF_COLLABORATOR_ADDRESS, "Collaborator Location");
        collaboratorPollingField = configGroup.addPreferenceComponent(PREF_POLLING_ADDRESS, "Collaborator Polling Location");
        remotePortSpinner = configGroup.addPreferenceComponent(PREF_POLLING_PORT, "Polling Port");
        ((SpinnerNumberModel) remotePortSpinner.getModel()).setMinimum(0);
        ((SpinnerNumberModel) remotePortSpinner.getModel()).setMaximum(65535);
        remotePortSpinner.setEditor(new JSpinner.NumberEditor(remotePortSpinner, "#"));


        sslEnabledCheckbox = panelBuilder.createPreferenceCheckBox(PREF_REMOTE_SSL_ENABLED, "Use SSL");
        trustSelfSignedCheckbox = panelBuilder.createPreferenceCheckBox(PREF_IGNORE_CERTIFICATE_ERRORS, "Ignore Certificate Errors");
        hostnameVerificationCheckbox = panelBuilder.createPreferenceCheckBox(PREF_SSL_HOSTNAME_VERIFICATION, "Enable SSL Hostname Verification");
        blockPublicCollaborator = panelBuilder.createPreferenceCheckBox(PREF_BLOCK_PUBLIC_COLLABORATOR, "Block Public Collaborator Server");
        proxyRequestsWithBurp = panelBuilder.createPreferenceCheckBox(PREF_PROXY_REQUESTS_WITH_BURP, "Proxy Polling Requests with Burp");

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
                    new JComponent[]{hostnameVerificationCheckbox, blockPublicCollaborator},
            }, new int[][]{
                    new int[]{1, 1},
                    new int[]{1, 1}
            }, Alignment.FILL, 1, 1);
        } catch (Exception e) {
            checkboxComponentsPanel = new JLabel("Could not build checkbox components panel");
        }
        configGroup.addComponent(checkboxComponentsPanel);


        //Control Panel
        statusLabel = new JLabel("Status: Not Running");
        statusLabel.setHorizontalAlignment(SwingConstants.CENTER);

        startStopButton = panelBuilder.createToggleButton("Start", actionEvent -> {
            JToggleButton thisButton = (JToggleButton) actionEvent.getSource();
            new Thread(() -> {
                if(thisButton.isSelected()){
                    try {
                        this.extension.startCollaboratorProxy();
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                    }
                }else{
                    this.extension.shutdownProxyService();
                }
            }).start();
        });
        JComponent autoStart = panelBuilder.createPreferenceCheckBox(PREF_AUTO_START, "Start Automatically on Load");
        JComponent controlGroup;
        try{
            controlGroup = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{statusLabel},
                    new JComponent[]{autoStart},
                    new JComponent[]{startStopButton},
            }, new int[][]{
                    new int[]{1},
                    new int[]{0},
                    new int[]{0},
            }, Alignment.FILL, 1.0, 1.0);
            controlGroup.setBorder(BorderFactory.createTitledBorder("Control"));
        }catch (Exception e){
            controlGroup = new JLabel("Could not build control panel :(");
        }


        ComponentGroup authenticationPanel = panelBuilder.createComponentGroup("Collaborator Authentication");
        enableAuthentication = panelBuilder.createPreferenceCheckBox(PREF_USE_AUTHENTICATION, "Enable Authentication");
        enableAuthentication.setBorder(BorderFactory.createEmptyBorder(0,0,10,30));
        enableAuthentication.addActionListener(e -> {
            secretArea.setEnabled(enableAuthentication.isSelected());
        });
        authenticationPanel.addComponent(enableAuthentication);

        ComponentGroup secretInputPanel = panelBuilder.createComponentGroup("Shared Authentication Secret");
        secretArea = panelBuilder.createPreferenceTextArea(PREF_SECRET);
        secretArea.setLineWrap(true);
        secretArea.setEnabled(extension.getPreferences().getSetting(PREF_USE_AUTHENTICATION));
        JScrollPane secretScrollPane = new JScrollPane(secretArea);
        secretScrollPane.setBorder(BorderFactory.createEmptyBorder());
        secretInputPanel.addComponent(secretScrollPane);

        JPanel authenticationWrapperPanel = panelBuilder.build(new Component[][]{
                new Component[]{authenticationPanel, secretInputPanel}
        }, new int[][]{
                new int[]{0, 1}
        }, Alignment.FILL, 1.0, 1.0);

        ComponentGroup logGroup = panelBuilder.createComponentGroup("Message Log");
        logArea = new JTextArea();
        logArea.setLineWrap(true);
        logArea.setWrapStyleWord(true);
        logArea.setBorder(null);
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, logArea.getFont().getSize()));
        JTextAreaAppender.addLog4j2TextAreaAppender(logArea);

        JScrollPane logScrollPane = new JScrollPane(logArea);
        logScrollPane.setBorder(BorderFactory.createLineBorder(Color.ORANGE));
        logScrollPane.setBorder(null);
        logScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        JPanel logLevelPanel = new JPanel(new GridLayout(1,2));
        JComboBox<Level> logLevelSelector = new JComboBox<>(new Level[]{Level.INFO, Level.DEBUG});
        logLevelSelector.setSelectedItem(LogManager.getRootLogger().getLevel());
        logLevelSelector.addActionListener(e -> {
            Level selectedLevel = (Level) logLevelSelector.getSelectedItem();
            extension.getPreferences().setSetting(PREF_LOG_LEVEL, selectedLevel);
            ((LoggerContext) LogManager.getContext(false))
                    .getLogger(EXTENSION_NAME).setLevel(selectedLevel);
        });
        logLevelPanel.add(new JLabel("Log Level: "));
        logLevelPanel.add(logLevelSelector);
        JButton clearButton = panelBuilder.createButton("Clear Logs", actionEvent -> {
            logArea.setText("");
        });

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
                    new JComponent[]{authenticationWrapperPanel, authenticationWrapperPanel},
                    new JComponent[]{logGroup, logGroup},
                }, new int[][]{
                    new int[]{0, 0},
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

    @Override
    public void beforeStartup() {
        SwingUtilities.invokeLater(() -> {
            startStopButton.setText("Starting...");
            startStopButton.setEnabled(false);
            startStopButton.setSelected(true);

            //Disable all other controls
            enableControls(false);
        });
    }

    @Override
    public void onStartupFail(String message) {
        SwingUtilities.invokeLater(() -> {
            startStopButton.setText("Start");
            startStopButton.setSelected(false);
            startStopButton.setEnabled(true);

            //Enable all other controls
            enableControls(true);

            statusLabel.setText("Status: Not Running");
        });
    }

    @Override
    public void onStartupSuccess(String message) {
        SwingUtilities.invokeLater(() -> {
            startStopButton.setText("Stop");
            startStopButton.setSelected(true);
            statusLabel.setText("Status: Listening on port " + localPortSpinner.getValue());

            //Disable all other controls
            enableControls(false);
            startStopButton.setEnabled(true);
            this.revalidate();
            this.repaint();
        });
    }

    @Override
    public void onShutdown() {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Status: Not Running");

            //Reenable other controls
            //Disable all other controls
            enableControls(true);
            startStopButton.setEnabled(true);
            startStopButton.setSelected(false);
            startStopButton.setText("Start");
            this.revalidate();
            this.repaint();
        });
    }

    private void enableControls(boolean enabled){
        localPortSpinner.setEnabled(enabled);
        collaboratorLocationField.setEnabled(enabled);
        collaboratorPollingField.setEnabled(enabled);
        remotePortSpinner.setEnabled(enabled);
        sslEnabledCheckbox.setEnabled(enabled);
        blockPublicCollaborator.setEnabled(enabled);
        trustSelfSignedCheckbox.setEnabled(enabled);
        hostnameVerificationCheckbox.setEnabled(enabled);
        proxyRequestsWithBurp.setEnabled(enabled);
        enableAuthentication.setEnabled(enabled);
        secretArea.setEnabled(enabled && enableAuthentication.isSelected());
    }
}
