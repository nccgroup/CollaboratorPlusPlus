package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventAdapter;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.context.ContextInfo;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;

class ContextTable extends JTable {

    ContextManager contextManager;
    HashMap<String, ContextInfo> infoMap;

    ContextTable(ContextManager contextManager) {
        this.contextManager = contextManager;
        this.infoMap = contextManager.getCollaboratorContexts();
        this.setModel(new ContextTableTableModel());
        this.setAutoResizeMode(AUTO_RESIZE_ALL_COLUMNS);
        for (int i = 3; i < 9; i++) {
            this.getColumnModel().getColumn(i).setMinWidth(100);
            this.getColumnModel().getColumn(i).setMaxWidth(100);
        }

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        this.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        this.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);

        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.setAutoCreateRowSorter(true);
        this.addContextMenuListener();

        this.registerCollaboratorEventListeners();
    }

    private void registerCollaboratorEventListeners() {
        this.contextManager.addEventListener(new CollaboratorEventAdapter() {
            @Override
            public void onPollingRequestSent(String collaboratorServer, String contextIdentifier, boolean isFirstPoll) {
                int rowIndex = contextManager.getIdentifiers().indexOf(contextIdentifier);
                try {
                    if (isFirstPoll) {
                        ((AbstractTableModel) ContextTable.this.getModel()).fireTableRowsInserted(rowIndex, rowIndex);
                    } else {
                        ((AbstractTableModel) ContextTable.this.getModel()).fireTableCellUpdated(rowIndex, 1);
                        ((AbstractTableModel) ContextTable.this.getModel()).fireTableCellUpdated(rowIndex, 2);
                    }
                } catch (Exception e) {
                    //TODO Fix before release.
                    CollaboratorPlusPlus.logManager.logError(e);
                    ((AbstractTableModel) ContextTable.this.getModel()).fireTableDataChanged();
                }
            }

            @Override
            public void onPollingResponseReceived(String collaboratorServer, String contextIdentifier, ArrayList<Interaction> interactions) {
                int rowIndex = contextManager.getIdentifiers().indexOf(contextIdentifier);
                try {
                    ((AbstractTableModel) ContextTable.this.getModel()).fireTableRowsUpdated(rowIndex, rowIndex);
                } catch (Exception e) {
                    //TODO Fix before release
                    CollaboratorPlusPlus.logManager.logError(e);
                    ((AbstractTableModel) ContextTable.this.getModel()).fireTableDataChanged();
                }
            }
        });
    }

    private void addContextMenuListener() {
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    ContextTable table = ContextTable.this;
                    ContextManager contextManager = table.contextManager;

                    int row = table.rowAtPoint(e.getPoint());
                    table.getSelectionModel().setSelectionInterval(row, row);
                    String identifier = (String) table.getValueAt(row, 0);
                    ContextInfo contextInfo = contextManager.getCollaboratorContext(identifier);
                    String shortIdentifier = identifier.length() > 15 ? identifier.substring(0,15) + "..." : identifier;

                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem headerItem = new JMenuItem(shortIdentifier);
                    headerItem.setEnabled(false);
                    popupMenu.add(headerItem);
                    popupMenu.add(new JPopupMenu.Separator());

                    JMenuItem deleteContextButton = new JMenuItem("Delete");
                    deleteContextButton.addActionListener(e1 -> {
                        int result = JOptionPane.showConfirmDialog(table, "Are you sure you wish to delete this context?" +
                                "\n\nIdentifier: " + contextInfo.getIdentifier() +
                                "\nInteractions: " + contextInfo.getInteractionEvents().size(), "Are you sure?", JOptionPane.YES_NO_OPTION);
                        if(result == JOptionPane.YES_OPTION) {
                            contextManager.deleteContext(contextInfo);
                            ((AbstractTableModel) table.getModel()).fireTableRowsDeleted(row, row);
                        }
                    });

                    popupMenu.add(deleteContextButton);
                    popupMenu.show(ContextTable.this, e.getX(), e.getY());
                }
            }
        });
    }

    private class ContextTableTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return contextManager.getCollaboratorContexts().size();
        }

        @Override
        public int getColumnCount() {
            return 9;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex > 3 ? Boolean.class : String.class;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0: return "Context Identifier";
                case 1: return "Server";
                case 2: return "Last Polled";
                case 3: return "Interactions";
                case 4: return "DNS";
                case 5: return "HTTP";
                case 6: return "HTTPS";
                case 7: return "SMTP";
                case 8: return "SMTPS";
            }
            return null;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= contextManager.getIdentifiers().size()) return null;
            String identifier = contextManager.getIdentifiers().get(rowIndex);
            ContextInfo contextInfo = contextManager.getCollaboratorContext(identifier);
            if(contextInfo == null) return null;
            switch (columnIndex) {
                case 0: return contextInfo.getIdentifier();
                case 1: return contextInfo.getCollaboratorAddress();
                case 2: return contextInfo.getLastPolled();
                case 3: return contextInfo.getInteractionEvents().size();
                case 4: return contextInfo.hasDNSEvent();
                case 5: return contextInfo.hasHTTPEvent();
                case 6: return contextInfo.hasHTTPSEvent();
                case 7: return contextInfo.hasSMTPEvent();
                case 8: return contextInfo.hasSMTPSEvent();
            }
            return null;
        }
    }
}
