package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventAdapter;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import org.bouncycastle.util.Arrays;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableCellRenderer;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.UUID;

public class InteractionsTable extends JTable {
    static SimpleDateFormat DATE_FORMAT = new SimpleDateFormat();

    private final ContextManager contextManager;
    CollaboratorContext collaboratorContext;

    InteractionsTable(ContextManager contextManager) {
        this.setModel(new InteractionsTableModel());
        this.setAutoCreateRowSorter(true);
        this.contextManager = contextManager;

        this.registerCollaboratorEventListeners();

        this.getSelectionModel().addListSelectionListener(e -> {
            if (collaboratorContext != null && collaboratorContext.getRecentInteractions() != null && this.getSelectedRows().length > 0) {
                for (int selectedRow : this.getSelectedRows()) {
                    UUID selectedUUID = collaboratorContext.getInteractionIds().get(convertRowIndexToModel(selectedRow));
                    collaboratorContext.getRecentInteractions().remove(selectedUUID);
                }
            }
        });

        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(SwingUtilities.isRightMouseButton(e)){
                    int[] selectedRows = InteractionsTable.this.getSelectedRows();
                    if(selectedRows.length == 0) return;
                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem header = new JMenuItem(selectedRows.length + " interactions");
                    header.setEnabled(false);
                    popupMenu.add(header);
                    popupMenu.add(new JPopupMenu.Separator());

                    //TODO Add event export and delete

//                    popupMenu.show(InteractionsTable.this, e.getX(), e.getY());
                }
            }
        });
    }

    private void registerCollaboratorEventListeners() {
        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingResponseReceived(CollaboratorContext collaboratorContext, ArrayList<Interaction> interactions) {
                SwingUtilities.invokeLater(() -> {
                    if (interactions.size() > 0 && InteractionsTable.this.collaboratorContext != null
                            && InteractionsTable.this.collaboratorContext.equals(collaboratorContext)) {
                        int initialSize = collaboratorContext.getInteractionEvents().size() - interactions.size();

                        try {
                            ((AbstractTableModel) InteractionsTable.this.getModel()).fireTableRowsInserted(
                                    initialSize, InteractionsTable.this.getModel().getRowCount() - 1);
                        } catch (Exception e) {
                            e.printStackTrace();
                            CollaboratorPlusPlus.logger.error(e);
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

        if (Arrays.contains(this.getSelectedRows(), row)) {
            c.setForeground(this.getSelectionForeground());
            c.setBackground(this.getSelectionBackground());
            return c;
        }

        UUID targetUUID = collaboratorContext.getInteractionIds().get(convertRowIndexToModel(row));
        if (collaboratorContext.getRecentInteractions() != null && collaboratorContext.getRecentInteractions().contains(targetUUID)) {
            c.setBackground(Color.ORANGE);
            c.setForeground(Color.WHITE);
        } else {
            c.setForeground(this.getForeground());
            c.setBackground(this.getBackground());
        }

        return c;
    }


    void setContext(CollaboratorContext collaboratorContext) {
        if (this.collaboratorContext != collaboratorContext) {
            this.collaboratorContext = collaboratorContext;
            ((AbstractTableModel) this.getModel()).fireTableDataChanged();
        }
    }

    private class InteractionsTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            if (collaboratorContext == null) return 0;
            return collaboratorContext.getInteractionEvents().size();
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
            if (collaboratorContext == null || rowIndex >= collaboratorContext.getInteractionEvents().size()) return null;
            Interaction interaction = collaboratorContext.getEventAtIndex(rowIndex);

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
