package com.nccgroup.collaboratorplusplus.extension.ui;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.JsonArray;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager.ContextInfo;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventListener;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import java.awt.*;

class ContextInformationPanel extends JSplitPane implements CollaboratorEventListener {

    private final CollaboratorContextManager contextManager;
    private final Preferences preferences;


    ContextInfo selectedContext;
    JTextField identifierLabel;
    JLabel lastPolledLabel;
    JTextArea interactionInformation;
    JButton pollNowButton;

    InteractionsTable interactionsTable;

    ContextInformationPanel(CollaboratorContextManager contextManager, Preferences preferences){
        super(VERTICAL_SPLIT);
        this.contextManager = contextManager;
        this.contextManager.addEventListener(this);
        this.preferences = preferences;
        this.interactionsTable = new InteractionsTable(contextManager);
        this.interactionsTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                int selectedRow = interactionsTable.getSelectedRow();
                if(selectedRow == -1) return;
                interactionInformation.setText(selectedContext.getInteractionEvents().get(selectedRow).toString());
            }
        });

        //TOP PANEL
        this.setTopComponent(buildTopComponent());
        this.setBottomComponent(new JScrollPane(interactionsTable));
    }

    void displayContext(ContextInfo contextInfo){
        if(contextInfo != null) {
            this.selectedContext = contextInfo;
            this.identifierLabel.setText(contextInfo.getIdentifier());
            this.lastPolledLabel.setText(contextInfo.getLastPolled().toLocaleString());
            this.interactionsTable.setContext(contextInfo);
        }else{
            this.selectedContext = null;
            this.identifierLabel.setText("N/A");
            this.lastPolledLabel.setText("N/A");
            this.interactionsTable.setContext(contextInfo);
        }
        this.interactionInformation.setText(null);
        pollNowButton.setEnabled(contextInfo != null);
    }

    private JComponent buildTopComponent(){
        PanelBuilder panelBuilder = new PanelBuilder(preferences);
        identifierLabel = new JTextField("N/A");
        identifierLabel.setEditable(false);
        identifierLabel.setBorder(null);
        lastPolledLabel = new JLabel("N/A");
        pollNowButton = new JButton("Poll Now");

        pollNowButton.setEnabled(false);
        pollNowButton.addActionListener(e -> {
            try {
                JsonArray interactions = contextManager.requestInteractions(selectedContext.getIdentifier());
                JOptionPane.showMessageDialog(this, "Retrieved " + interactions.size()
                        + " interactions from the Collaborator server.", "Interaction Polling",
                        JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception e1) {
                JOptionPane.showMessageDialog(this, "Could not retrieve interactions:\n"
                    + e1.getMessage(), "Polling Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        interactionInformation = new JTextArea();
        interactionInformation.setEditable(false);
        interactionInformation.setWrapStyleWord(true);
        interactionInformation.setLineWrap(true);
        JScrollPane infoScrollPane = new JScrollPane(interactionInformation);
        infoScrollPane.setPreferredSize(new Dimension(300, 250));

        try{
            JLabel idTitle = new JLabel("ID: ");
            JLabel lpTitle = new JLabel("Last Polled: ");
            idTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 30));
            lpTitle.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 30));
            return panelBuilder.build(new JComponent[][]{
                    new JComponent[] {idTitle, identifierLabel, pollNowButton},
                    new JComponent[] {lpTitle, lastPolledLabel, pollNowButton},
                    new JComponent[] {infoScrollPane, infoScrollPane, infoScrollPane}
            }, new int[][]{
                    new int[]{0, 1, 0},
                    new int[]{0, 1, 0},
                    new int[]{0, 100, 0}
            }, Alignment.CENTER, 1.0, 1.0);
        }catch (Exception e){
            return new JLabel("Could not build Context Information panel! :(");
        }
    }

    @Override
    public void onPollingRequestSent(String biid, boolean isFirstPoll) {
        if(selectedContext != null && biid.equalsIgnoreCase(selectedContext.getIdentifier())){
            displayContext(contextManager.getInteractions(biid));
        }
    }

    @Override
    public void onPollingResponseRecieved(String biid, JsonArray interactions) {
        if(selectedContext != null && biid.equalsIgnoreCase(selectedContext.getIdentifier())){
            displayContext(contextManager.getInteractions(biid));
        }
    }
}
