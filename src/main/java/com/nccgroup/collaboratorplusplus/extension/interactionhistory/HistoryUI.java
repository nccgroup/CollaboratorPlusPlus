package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;

import javax.swing.*;
import java.awt.*;

public class HistoryUI extends JSplitPane {

    private final ContextManager contextManager;
    private final Preferences preferences;
    private ContextTable contextTable;
    private ContextInformationPanel contextInformationPanel;

    public HistoryUI(ContextManager contextManager, Preferences preferences){
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
                Object selectedComponent = contextTable.getPathForRow(selectedRow).getLastPathComponent();
                if(selectedComponent instanceof CollaboratorContext) {
                    SwingUtilities.invokeLater(() ->
                            contextInformationPanel.displayContext((CollaboratorContext) selectedComponent));
                }else{
                    SwingUtilities.invokeLater(() -> contextInformationPanel.displayContext(null));
                }
            }
        });

        this.setTopComponent(contextScrollPane);
        this.setBottomComponent(contextInformationPanel);
    }
}
