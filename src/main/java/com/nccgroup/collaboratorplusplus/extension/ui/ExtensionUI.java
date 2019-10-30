package com.nccgroup.collaboratorplusplus.extension.ui;

import burp.IExtensionStateListener;
import burp.ITab;
import com.coreyd97.BurpExtenderUtilities.PopOutPanel;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.interactionhistory.HistoryUI;

import javax.swing.*;
import java.awt.*;

import static com.nccgroup.collaboratorplusplus.extension.Globals.EXTENSION_NAME;

public class ExtensionUI implements ITab, IExtensionStateListener {

    private final CollaboratorPlusPlus extension;
    private PopOutPanel popOutPanel;
    private JMenuBar menuBar;
    private JMenu extensionMenu;

    public ExtensionUI(CollaboratorPlusPlus extension){
        this.extension = extension;
        CollaboratorPlusPlus.callbacks.registerExtensionStateListener(this);
        this.popOutPanel = new PopOutPanel(buildMainPanel(), EXTENSION_NAME);
    }

    private JComponent buildMainPanel(){
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Config", new ConfigUI(extension));
        tabbedPane.addTab("Interaction History", new HistoryUI(extension.getContextManager(), extension.getPreferences()));
        tabbedPane.addTab("About", new AboutUI(extension));
        return tabbedPane;
    }

    public void addMenuItemsToBurp(){
        JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(this.popOutPanel);
        menuBar = rootFrame.getJMenuBar();
        if(menuBar != null) {
            extensionMenu = new JMenu("Collaborator++");
            extensionMenu.add(popOutPanel.getPopoutMenuItem());
            menuBar.add(extensionMenu, menuBar.getMenuCount() - 1);
        }
    }

    public void removeMenuItemsFromBurp(){
        if(menuBar != null && extensionMenu != null){
            menuBar.remove(extensionMenu);
        }
    }

    public JComponent getTabForExtension(){
        JTabbedPane mainPane = getBurpTabbedPane();
        int tabIndex = mainPane.indexOfComponent(this.popOutPanel);
        return (JComponent) mainPane.getTabComponentAt(tabIndex);
    }

    public JTabbedPane getBurpTabbedPane(){
        return (JTabbedPane) this.popOutPanel.getParent();
    }

    @Override
    public void extensionUnloaded() {
        removeMenuItemsFromBurp();
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return popOutPanel;
    }
}
