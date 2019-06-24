package com.nccgroup.collaboratorplusplus.extension.ui;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager;

import javax.swing.*;

public class HistoryUI extends JSplitPane {

    private final CollaboratorContextManager contextManager;
    private final Preferences preferences;
    private ContextTable contextTable;
    private ContextInformationPanel contextInformationPanel;

    public HistoryUI(CollaboratorContextManager contextManager, Preferences preferences){
        super(HORIZONTAL_SPLIT);
        this.contextManager = contextManager;
        this.preferences = preferences;
        buildMainPanel();
    }

    private void buildMainPanel(){
        contextTable = new ContextTable(contextManager);
        JScrollPane interactionScrollPane = new JScrollPane(contextTable);
        contextInformationPanel = new ContextInformationPanel(contextManager, preferences);

        contextTable.getSelectionModel().addListSelectionListener(e -> {
            int selectedRow = contextTable.getSelectedRow();
            if(selectedRow == -1) {
                contextInformationPanel.displayContext(null);
            }else{
                String id = (String) contextTable.getValueAt(selectedRow, 0);
                contextInformationPanel.displayContext(contextManager.getInteractions(id));
            }
        });

        this.setLeftComponent(interactionScrollPane);
        this.setRightComponent(contextInformationPanel);

        SwingUtilities.invokeLater(() -> {
            this.setDividerLocation(0.4);
        });
    }
}
