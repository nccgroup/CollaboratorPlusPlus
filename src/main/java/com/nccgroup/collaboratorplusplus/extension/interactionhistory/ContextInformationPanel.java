package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventAdapter;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.ContextInfo;
import com.nccgroup.collaboratorplusplus.utilities.SelectableLabel;

import javax.swing.*;
import java.awt.*;

class ContextInformationPanel extends JPanel {

    private final CollaboratorContextManager contextManager;
    private final Preferences preferences;

    ContextInfo selectedContext;
    JTextField identifierLabel;
    JLabel lastPolledLabel;
    InteractionInfoPanel interactionInformationPanel;
    JButton pollNowButton;

    InteractionsTable interactionsTable;

    ContextInformationPanel(CollaboratorContextManager contextManager, Preferences preferences){
        super(new BorderLayout());
        this.contextManager = contextManager;
        this.preferences = preferences;
        this.interactionsTable = new InteractionsTable(contextManager);
        this.interactionInformationPanel = new InteractionInfoPanel(preferences);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        splitPane.setLeftComponent(new JScrollPane(interactionsTable));
        splitPane.setRightComponent(interactionInformationPanel);

        this.add(buildIDInfoPane(), BorderLayout.NORTH);
        this.add(splitPane, BorderLayout.CENTER);

        registerListeners();
    }

    private JComponent buildIDInfoPane(){
        PanelBuilder panelBuilder = new PanelBuilder(preferences);
        identifierLabel = new SelectableLabel("N/A");
        lastPolledLabel = new JLabel("N/A");
        pollNowButton = new JButton("Poll Now");

        pollNowButton.setEnabled(false);
        pollNowButton.addActionListener(e -> {
            try {
                contextManager.requestInteractions(selectedContext.getIdentifier());
            } catch (Exception e1) {
                e1.printStackTrace();
                JOptionPane.showMessageDialog(this, "Could not retrieve interactions:\n"
                        + e1.getMessage(), "Polling Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        try{
            JLabel idTitle = new JLabel("ID: ");
            JLabel lpTitle = new JLabel("Last Polled: ");
            idTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 30));
            lpTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 30));
            return panelBuilder.build(new JComponent[][]{
                    new JComponent[] {idTitle, identifierLabel, pollNowButton},
                    new JComponent[] {lpTitle, lastPolledLabel, pollNowButton},
            }, new int[][]{
                    new int[]{0, 1, 0},
                    new int[]{0, 1, 0},
                    new int[]{0, 100, 0}
            }, Alignment.CENTER, 1.0, 1.0);
        }catch (Exception e){
            return new JLabel("Could not build Context Information panel! :(");
        }
    }

    void displayContext(ContextInfo contextInfo){
        if(contextInfo != null) {
            this.selectedContext = contextInfo;
            this.interactionsTable.setContext(contextInfo);
            this.identifierLabel.setText(contextInfo.getIdentifier());
            this.lastPolledLabel.setText(contextInfo.getLastPolled().toString());
        }else{
            this.selectedContext = null;
            this.interactionsTable.setContext(contextInfo);
            this.identifierLabel.setText("N/A");
            this.lastPolledLabel.setText("N/A");
        }
        this.interactionInformationPanel.setActiveInteraction(null);
        pollNowButton.setEnabled(contextInfo != null);
    }

    private void registerListeners(){
        this.interactionsTable.getSelectionModel().addListSelectionListener(e -> {
            int selectedRow = interactionsTable.getSelectedRow();
            if(selectedRow == -1) return;
            interactionInformationPanel.setActiveInteraction(selectedContext.getEventAtIndex(selectedRow));
        });

        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingRequestSent(String biid, boolean isFirstPoll) {
                if(selectedContext != null && biid.equalsIgnoreCase(selectedContext.getIdentifier())){
                    lastPolledLabel.setText(selectedContext.getLastPolled().toString());
                    new Thread(() -> {
                        Color foreground = lastPolledLabel.getForeground();
                        lastPolledLabel.setForeground(Color.ORANGE);
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                        lastPolledLabel.setForeground(foreground);
                    }).start();
                }
            }
        });
    }
}
