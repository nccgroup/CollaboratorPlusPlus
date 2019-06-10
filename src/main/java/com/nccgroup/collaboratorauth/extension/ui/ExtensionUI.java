package com.nccgroup.collaboratorauth.extension.ui;

import burp.ITab;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;

import javax.swing.*;
import java.awt.*;

import static com.nccgroup.collaboratorauth.extension.Globals.EXTENSION_NAME;

public class ExtensionUI extends JTabbedPane implements ITab {

    private final JPanel configPanel;
    private final JPanel aboutPanel;

    public ExtensionUI(CollaboratorAuthenticator extension){
        this.configPanel = new ConfigUI(extension);
        this.aboutPanel = new AboutUI(extension);
        this.addTab("Config", configPanel);
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
