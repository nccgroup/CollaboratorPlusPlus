package com.nccgroup.collaboratorplusplus.extension.ui;

import burp.ITab;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;

import javax.swing.*;
import java.awt.*;

import static com.nccgroup.collaboratorplusplus.extension.Globals.EXTENSION_NAME;

public class ExtensionUI extends JTabbedPane implements ITab {

    private final JComponent configPanel;
    private final JComponent historyPanel;
    private final JComponent aboutPanel;

    public ExtensionUI(CollaboratorPlusPlus extension){
        this.configPanel = new ConfigUI(extension);
        this.historyPanel = new HistoryUI(extension.getContextManager(), extension.getPreferences());
        this.aboutPanel = new AboutUI(extension);
        this.addTab("Config", configPanel);
        this.addTab("Interaction History", historyPanel);
        this.addTab("About", aboutPanel);
    }

    @Override
    public String getTabCaption() {
        return EXTENSION_NAME;
    }

    @Override
    public Component getUiComponent() {
        return this;
    }
}
