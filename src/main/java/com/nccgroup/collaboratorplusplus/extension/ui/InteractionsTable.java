package com.nccgroup.collaboratorplusplus.extension.ui;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventListener;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;

import java.text.SimpleDateFormat;
import java.util.Date;

import static com.nccgroup.collaboratorplusplus.extension.CollaboratorContextManager.*;

public class InteractionsTable extends JTable implements CollaboratorEventListener {
    static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat();

    private final CollaboratorContextManager contextManager;
    ContextInfo contextInfo;

    InteractionsTable(CollaboratorContextManager contextManager){
        this.setModel(new InteractionsTableModel());
        this.setAutoCreateRowSorter(true);
        this.contextManager = contextManager;
        this.contextManager.addEventListener(this);
    }

    void setContext(ContextInfo collaboratorContext){
        this.contextInfo = collaboratorContext;

        ((AbstractTableModel) this.getModel()).fireTableDataChanged();
    }

    @Override
    public void onPollingRequestSent(String biid) {}

    @Override
    public void onPollingResponseRecieved(String biid, JsonArray interactions) {
        if(this.contextInfo != null && this.contextInfo.getIdentifier().equalsIgnoreCase(biid)){
            int initialSize = contextInfo.getInteractionEvents().size()-interactions.size();
            try {
                ((AbstractTableModel) this.getModel()).fireTableRowsInserted(
                        initialSize, initialSize + interactions.size());
            }catch (Exception ignored){}
        }
    }

    private class InteractionsTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            if(contextInfo == null) return 0;
            return contextInfo.getInteractionEvents().size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public String getColumnName(int column) {
            switch (column){
                case 0: return "Interaction String";
                case 1: return "Protocol";
                case 2: return "Time";
                case 3: return "Client";
            }
            return null;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if(contextInfo == null || rowIndex >= contextInfo.getInteractionEvents().size()) return null;
            JsonObject interaction = contextInfo.getInteractionEvents().get(rowIndex).getAsJsonObject();

            switch (columnIndex){
                case 0: return interaction.get("interactionString").getAsString();
                case 1: return interaction.get("protocol").getAsString().toUpperCase();
                case 2: return DATE_FORMAT.format(new Date(interaction.get("time").getAsLong()));
                case 3: return interaction.get("client").getAsString();
            }

            return null;
        }
    }
}
