package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContextManager;

import javax.swing.*;
import java.awt.*;

public class HistoryUI extends JSplitPane {

    private final CollaboratorContextManager contextManager;
    private final Preferences preferences;
    private ContextTable contextTable;
    private ContextInformationPanel contextInformationPanel;

    public HistoryUI(CollaboratorContextManager contextManager, Preferences preferences){
        super(VERTICAL_SPLIT);
        this.contextManager = contextManager;
        this.preferences = preferences;
        buildMainPanel();
    }

    private void buildMainPanel(){
        contextTable = new ContextTable(contextManager);
        JScrollPane contextScrollPane = new JScrollPane(contextTable);
        contextScrollPane.setMinimumSize(new Dimension(0, 75));
        contextInformationPanel = new ContextInformationPanel(contextManager, preferences);

        contextTable.getSelectionModel().addListSelectionListener(e -> {
            int selectedRow = contextTable.getSelectedRow();
            if(selectedRow == -1) {
                SwingUtilities.invokeLater(() -> contextInformationPanel.displayContext(null));
            }else{
                String id = (String) contextTable.getValueAt(selectedRow, 0);
                SwingUtilities.invokeLater(() ->
                        contextInformationPanel.displayContext(contextManager.getCollaboratorContext(id)));
            }
        });

        this.setTopComponent(contextScrollPane);
        this.setBottomComponent(contextInformationPanel);
    }
}
