package com.nccgroup.collaboratorauth.extension.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class ConfigUI implements ITab {

    private final CollaboratorAuthenticator extension;
    private final JPanel mainPanel;

    public ConfigUI(CollaboratorAuthenticator extension){
        this.extension = extension;
        this.mainPanel = buildMainPanel();
    }

    public JPanel buildMainPanel(){
        JPanel mainPanel = new JPanel();
        JButton startButton = new JButton("Start");
        startButton.addActionListener((ae) -> {
            try {
                this.extension.startCollaboratorProxy((int) (8081 + Math.floor(Math.random()*1000)));
            }catch (IOException | NoSuchAlgorithmException e){
                e.printStackTrace();
            }
        });
        JButton stopButton = new JButton("Stop");
        stopButton.addActionListener((ae) -> {
            this.extension.stopCollaboratorProxy();
        });

        JButton breakpointButton = new JButton("BreakPoint");
        breakpointButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                System.out.println("BreakPoint");
                CollaboratorAuthenticator.callbacks.createBurpCollaboratorClientContext().fetchAllCollaboratorInteractions();
            }
        });

        mainPanel.add(startButton);
        mainPanel.add(stopButton);
        mainPanel.add(breakpointButton);

        return mainPanel;
    }

    @Override
    public String getTabCaption() {
        return CollaboratorAuthenticator.extensionName;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
