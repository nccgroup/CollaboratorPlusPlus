package com.nccgroup.collaboratorplusplus.extension.ui;

import com.google.gson.JsonArray;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.HashMap;

import static com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager.*;

class ContextTable extends JTable implements CollaboratorEventListener {

    CollaboratorContextManager contextManager;
    HashMap<String, ContextInfo> infoMap;

    ContextTable(CollaboratorContextManager contextManager){
        this.contextManager = contextManager;
        this.infoMap = contextManager.getCollaboratorHistory();
        this.setModel(new ContextTableTableModel());
        this.setAutoResizeMode(AUTO_RESIZE_ALL_COLUMNS);
        this.getColumnModel().getColumn(2).setMinWidth(100);
        this.getColumnModel().getColumn(2).setMaxWidth(100);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.setAutoCreateRowSorter(true);
        this.contextManager.addEventListener(this);
    }

    @Override
    public void onPollingRequestSent(String biid) {
        int rowIndex = contextManager.getIdentifiers().indexOf(biid);
        ((AbstractTableModel) this.getModel()).fireTableRowsUpdated(rowIndex, rowIndex);
    }

    @Override
    public void onPollingResponseRecieved(String biid, JsonArray interactions) {
        int rowIndex = contextManager.getIdentifiers().indexOf(biid);
        ((AbstractTableModel) this.getModel()).fireTableRowsUpdated(rowIndex, rowIndex);
    }

    private class ContextTableTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return contextManager.getCollaboratorHistory().size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public String getColumnName(int column) {
            switch (column){
                case 0: return "Context Identifier";
                case 1: return "Last Polled";
                case 2: return "Interactions";
            }
            return null;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if(rowIndex >= contextManager.getIdentifiers().size()) return null;
            String identifier = contextManager.getIdentifiers().get(rowIndex);
            if(columnIndex == 0) return identifier;
            ContextInfo contextInfo = contextManager.getInteractions(identifier);
            switch (columnIndex){
                case 1: return contextInfo.getLastPolled();
                case 2: return contextInfo.getInteractionEvents().size();
            }
            return null;
        }
    }
}
