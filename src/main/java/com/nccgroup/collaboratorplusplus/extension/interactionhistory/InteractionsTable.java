package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventAdapter;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.context.ContextInfo;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.UUID;

public class InteractionsTable extends JTable {
    static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat();

    private final ContextManager contextManager;
    ContextInfo contextInfo;

    InteractionsTable(ContextManager contextManager) {
        this.setModel(new InteractionsTableModel());
        this.setAutoCreateRowSorter(true);
        this.contextManager = contextManager;

        this.registerCollaboratorEventListeners();

        this.getSelectionModel().addListSelectionListener(e -> {
            if (contextInfo != null && contextInfo.getRecentInteractions() != null && this.getSelectedRow() != -1) {
                UUID selectedUUID = contextInfo.getInteractionIds().get(convertRowIndexToModel(this.getSelectedRow()));
                contextInfo.getRecentInteractions().remove(selectedUUID);
            }
        });
    }

    private void registerCollaboratorEventListeners() {
        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingResponseReceived(String collaboratorServer, String contextIdentifier, ArrayList<Interaction> interactions) {
                SwingUtilities.invokeLater(() -> {
                    if (interactions.size() > 0 && InteractionsTable.this.contextInfo != null
                            && InteractionsTable.this.contextInfo.getIdentifier().equalsIgnoreCase(contextIdentifier)) {
                        int initialSize = contextInfo.getInteractionEvents().size() - interactions.size();

                        try {
                            ((AbstractTableModel) InteractionsTable.this.getModel()).fireTableRowsInserted(
                                    initialSize, InteractionsTable.this.getModel().getRowCount() - 1);
                        } catch (Exception e) {
                            e.printStackTrace();
                            CollaboratorPlusPlus.logManager.logError(e);
                        }
                    }
                });
            }
        });
    }

    //Sneak in row coloring just before rendering the cell.
    //Highlight recent interactions which have not yet been viewed.
    @Override
    public Component prepareRenderer(TableCellRenderer renderer, int row, int column) {
        Component c = super.prepareRenderer(renderer, row, column);

        if (row == this.getSelectedRow()) {
            c.setForeground(this.getSelectionForeground());
            c.setBackground(this.getSelectionBackground());
            return c;
        }

        UUID targetUUID = contextInfo.getInteractionIds().get(convertRowIndexToModel(row));
        if (contextInfo.getRecentInteractions() != null && contextInfo.getRecentInteractions().contains(targetUUID)) {
            c.setBackground(Color.ORANGE);
            c.setForeground(Color.WHITE);
        } else {
            c.setForeground(this.getForeground());
            c.setBackground(this.getBackground());
        }

        return c;
    }


    void setContext(ContextInfo collaboratorContext) {
        if (this.contextInfo != collaboratorContext) {
            this.contextInfo = collaboratorContext;
            ((AbstractTableModel) this.getModel()).fireTableDataChanged();
        }
    }

    private class InteractionsTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            if (contextInfo == null) return 0;
            return contextInfo.getInteractionEvents().size();
        }

        @Override
        public int getColumnCount() {
            return 4;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "Interaction String";
                case 1:
                    return "Protocol";
                case 2:
                    return "Time";
                case 3:
                    return "Client";
            }
            return null;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (contextInfo == null || rowIndex >= contextInfo.getInteractionEvents().size()) return null;
            Interaction interaction = contextInfo.getEventAtIndex(rowIndex);

            switch (columnIndex) {
                case 0:
                    return interaction.getInteractionString();
                case 1:
                    return interaction.getInteractionType();
                case 2:
                    return DATE_FORMAT.format(interaction.getTime());
                case 3:
                    return interaction.getClient();
            }

            return null;
        }
    }
}
