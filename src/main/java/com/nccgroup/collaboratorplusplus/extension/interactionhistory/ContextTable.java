package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventAdapter;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorServer;
import com.nccgroup.collaboratorplusplus.extension.context.ContextManager;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import org.jdesktop.swingx.JXTreeTable;
import org.jdesktop.swingx.treetable.AbstractTreeTableModel;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.tree.TreePath;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

class ContextTable extends JXTreeTable {

    ContextManager contextManager;

    ContextTable(ContextManager contextManager) {
        this.contextManager = contextManager;

        ContextTreeTableModel model = new ContextTreeTableModel(this.contextManager.getCollaboratorServers());
        model.registerListeners();
        this.setTreeTableModel(model);

        this.setAutoResizeMode(AUTO_RESIZE_ALL_COLUMNS);

        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(SwingConstants.CENTER);
        this.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        this.getColumnModel().getColumn(2).setCellRenderer(centerRenderer);
        for (int i = 3; i < 8; i++) {
            TableColumn col = this.getColumnModel().getColumn(i);
            col.setCellRenderer(centerRenderer);
            col.setMinWidth(100);
            col.setMaxWidth(100);
        }

        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.setAutoCreateRowSorter(true);
        this.addContextMenuListener();
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
                    TreePath selectedPath = table.getPathForRow(row);

                    JPopupMenu popupMenu = new JPopupMenu();
                    JMenuItem headerItem;
                    JMenuItem exportMenuItem = new JMenuItem("Export - Not Implemented");
                    JMenuItem deleteMenuItem = new JMenuItem("Delete");

                    if (selectedPath.getLastPathComponent() instanceof CollaboratorServer) {
                        CollaboratorServer collaboratorServer = (CollaboratorServer) selectedPath.getLastPathComponent();
                        headerItem = new JMenuItem((collaboratorServer).getCollaboratorAddress());
                        //Now add event listeners to delete and export buttons
                        deleteMenuItem.addActionListener(e1 -> {
                            String warningMessage = String.format("Are you sure you wish to delete all contexts" +
                                            " associated with this server?\n\nServer: %s\nContexts: %d\nTotal Interactions: %d",
                                    collaboratorServer.getCollaboratorAddress(),
                                    collaboratorServer.getContexts().size(),
                                    collaboratorServer.getTotalInteractions());
                            int result = JOptionPane.showConfirmDialog(table, warningMessage, "Are you sure?", JOptionPane.YES_NO_OPTION);
                            if (result == JOptionPane.YES_OPTION) {
                                contextManager.removeCollaboratorServer(collaboratorServer);
                            }
                        });
                    } else if (selectedPath.getLastPathComponent() instanceof CollaboratorContext) {
                        CollaboratorContext context = (CollaboratorContext) selectedPath.getLastPathComponent();
                        headerItem = new JMenuItem(context.getIdentifier());
                        //Now add event listeners to delete and export buttons
                        deleteMenuItem.addActionListener(e1 -> {
                            int result = JOptionPane.showConfirmDialog(table, "Are you sure you wish to delete this context?" +
                                    "\n\nIdentifier: " + context.getIdentifier() +
                                    "\nInteractions: " + context.getInteractionEvents().size(), "Are you sure?", JOptionPane.YES_NO_OPTION);
                            if (result == JOptionPane.YES_OPTION) {
                                contextManager.removeCollaboratorContext(context);
                            }
                        });

                    } else {
                        return;
                    }

                    headerItem.setEnabled(false);
                    popupMenu.add(headerItem);
                    popupMenu.add(new JPopupMenu.Separator());
//                    popupMenu.add(exportMenuItem);
                    popupMenu.add(deleteMenuItem);
                    popupMenu.show(ContextTable.this, e.getX(), e.getY());
                }
            }
        });
    }

    private class ContextTreeTableModel extends AbstractTreeTableModel {

        ArrayList<CollaboratorServer> servers;

        ContextTreeTableModel(ArrayList<CollaboratorServer> servers) {
            super(new Object());
            this.servers = servers;

        }


        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex > 2 ? Integer.class : String.class;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "Context";
                case 1:
                    return "Last Polled";
                case 2:
                    return "Interactions";
                case 3:
                    return "DNS";
                case 4:
                    return "HTTP";
                case 5:
                    return "HTTPS";
                case 6:
                    return "SMTP";
                case 7:
                    return "SMTPS";
            }
            return null;
        }


        @Override
        public Object getValueAt(Object node, int columnIndex) {
            if (node instanceof CollaboratorServer) {
                switch (columnIndex) {
                    case 0:
                        return ((CollaboratorServer) node).getCollaboratorAddress();
                    case 2:
                        return ((CollaboratorServer) node).getTotalInteractions();
                    case 3:
                        return ((CollaboratorServer) node).getDnsEventCount();
                    case 4:
                        return ((CollaboratorServer) node).getHttpEventCount();
                    case 5:
                        return ((CollaboratorServer) node).getHttpsEventCount();
                    case 6:
                        return ((CollaboratorServer) node).getSmtpEventCount();
                    case 7:
                        return ((CollaboratorServer) node).getSmtpsEventCount();
                    default:
                        return null;
                }
            }
            if (node instanceof CollaboratorContext) {
                switch (columnIndex) {
                    case 0:
                        return ((CollaboratorContext) node).getIdentifier();
                    case 1:
                        return ((CollaboratorContext) node).getLastPolled();
                    case 2:
                        return ((CollaboratorContext) node).getInteractionEvents().size();
                    case 3:
                        return ((CollaboratorContext) node).getDNSInteractionCount();
                    case 4:
                        return ((CollaboratorContext) node).getHttpInteractionCount();
                    case 5:
                        return ((CollaboratorContext) node).getHttpsInteractionCount();
                    case 6:
                        return ((CollaboratorContext) node).getSMTPInteractionCount();
                    case 7:
                        return ((CollaboratorContext) node).getSMTPSInteractionCount();
                }
            }
            return null;
        }

        @Override
        public Object getChild(Object o, int i) {
            if (o == this.getRoot()) {
                if (i == -1) return null;
                return contextManager.getCollaboratorServers().get(i);
            }
            if (o instanceof CollaboratorServer) {
                if (i == -1) return null;
                return ((CollaboratorServer) o).getContexts().get(i);
            }
            return null;
        }

        @Override
        public int getChildCount(Object o) {
            if (o == this.getRoot())
                return contextManager.getCollaboratorServers().size();
            if (o instanceof CollaboratorServer)
                return ((CollaboratorServer) o).getContexts().size();
            return 0;
        }

        @Override
        public int getIndexOfChild(Object o, Object o1) {
            if (o == null) return contextManager.getCollaboratorServers().indexOf(o1);
            if (o instanceof CollaboratorServer) return ((CollaboratorServer) o).getContexts().indexOf(o1);
            return -1;
        }

        @Override
        public boolean isLeaf(Object node) {
            return node instanceof CollaboratorContext;
        }

        private void registerListeners() {
            contextManager.addEventListener(new CollaboratorEventAdapter() {
                @Override
                public void onCollaboratorServerRegistered(CollaboratorServer collaboratorServer, int index) {
                    modelSupport.fireChildAdded(new TreePath(getRoot()), index, collaboratorServer);
                }

                @Override
                public void onCollaboratorServerRemoved(CollaboratorServer collaboratorServer, int index) {
                    modelSupport.fireChildRemoved(new TreePath(getRoot()), index, collaboratorServer);
                }

                @Override
                public void onCollaboratorContextRegistered(CollaboratorContext collaboratorContext, int index) {
                    modelSupport.fireChildAdded(new TreePath(new Object[]{getRoot(), collaboratorContext.getCollaboratorServer()}),
                            index, collaboratorContext);
                }

                @Override
                public void onCollaboratorContextRemoved(CollaboratorContext collaboratorContext, int index) {
                    modelSupport.fireChildRemoved(new TreePath(new Object[]{getRoot(), collaboratorContext.getCollaboratorServer()}), index, collaboratorContext);
                }

                @Override
                public void onPollingRequestSent(CollaboratorContext collaboratorContext) {
                    modelSupport.fireChildChanged(new TreePath(new Object[]{getRoot(), collaboratorContext.getCollaboratorServer()}),
                            collaboratorContext.getCollaboratorServer().getContexts().indexOf(collaboratorContext),
                            collaboratorContext);
                }

                @Override
                public void onPollingResponseReceived(CollaboratorContext collaboratorContext, ArrayList<Interaction> interactions) {
                    modelSupport.firePathChanged(new TreePath(new Object[]{collaboratorContext.getCollaboratorServer()}));
                }
            });
        }
    }
}
