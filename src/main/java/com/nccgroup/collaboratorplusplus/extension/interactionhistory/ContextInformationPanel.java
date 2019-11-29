package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventAdapter;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import com.nccgroup.collaboratorplusplus.utilities.SelectableLabel;

import javax.swing.*;
import java.awt.*;

class ContextInformationPanel extends JPanel {

    private final ContextManager contextManager;
    private final Preferences preferences;

    CollaboratorContext selectedContext;
    JTextField identifierLabel;
    JLabel lastPolledLabel;
    InteractionInfoPanel interactionInformationPanel;
    JButton pollNowButton;
    Color originalLastPolledColor;

    InteractionsTable interactionsTable;

    ContextInformationPanel(ContextManager contextManager, Preferences preferences){
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
        originalLastPolledColor = lastPolledLabel.getForeground();

        pollNowButton.setEnabled(false);
        pollNowButton.addActionListener(e -> {
            try {
                contextManager.requestInteractions(selectedContext);
            } catch (Exception e1) {
                JOptionPane.showMessageDialog(this, "Could not retrieve interactions:\n"
                        + e1.getMessage(), "Polling Error", JOptionPane.ERROR_MESSAGE);
            }
        });

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
    }

    void displayContext(CollaboratorContext collaboratorContext){
        if(collaboratorContext != null) {
            this.selectedContext = collaboratorContext;
            this.interactionsTable.setContext(collaboratorContext);
            this.identifierLabel.setText(collaboratorContext.getIdentifier());
            this.lastPolledLabel.setText(collaboratorContext.getLastPolled().toString());
        }else{
            this.selectedContext = null;
            this.interactionsTable.setContext(null);
            this.identifierLabel.setText("N/A");
            this.lastPolledLabel.setText("N/A");
        }
        this.interactionInformationPanel.setActiveInteraction(null);
        pollNowButton.setEnabled(collaboratorContext != null);
    }

    private void registerListeners(){
        this.interactionsTable.getSelectionModel().addListSelectionListener(e -> {
            int selectedRow = interactionsTable.getSelectedRow();
            if(selectedRow == -1) return;
            Interaction selectedInteraction = selectedContext.getEventAtIndex(interactionsTable.convertRowIndexToModel(selectedRow));
            interactionInformationPanel.setActiveInteraction(selectedInteraction);
        });

        //Update last polled text when poll request sent
        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingRequestSent(CollaboratorContext collaboratorContext) {
                if(selectedContext != null && selectedContext.equals(collaboratorContext)){
                    lastPolledLabel.setText(selectedContext.getLastPolled().toString());
                    lastPolledLabel.setForeground(Color.ORANGE);

                    Timer colorResetTimer = new Timer(1000, e -> lastPolledLabel.setForeground(originalLastPolledColor));
                    colorResetTimer.setRepeats(false);
                    colorResetTimer.start();
                }
            }
        });
    }
}
