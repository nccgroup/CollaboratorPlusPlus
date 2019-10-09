package com.nccgroup.collaboratorplusplus.extension.interactionhistory;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.context.DNSInteraction;
import com.nccgroup.collaboratorplusplus.extension.context.HTTPInteraction;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import com.nccgroup.collaboratorplusplus.extension.context.SMTPInteraction;

import javax.swing.*;
import java.awt.*;
import java.util.Date;

public class InteractionInfoPanel extends JTabbedPane {

    private final Preferences preferences;
    private Interaction selectedInteraction;
    private JPanel infoPanel;
    private JTextArea rawArea;
    private JLabel noInteractionLabel = new JLabel("No interaction selected.");

    public InteractionInfoPanel(Preferences preferences){
        this.preferences = preferences;
        this.infoPanel = createInfoInnerPanel();
        this.infoPanel.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));

        this.addTab("Info", createInfoWrapperPanel(this.infoPanel));
        this.addTab("Raw", createRawPanel());
    }

    private JPanel createInfoInnerPanel(){
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(noInteractionLabel, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createInfoWrapperPanel(JPanel innerPanel){
        return new PanelBuilder(null).build(innerPanel, Alignment.FILL, 1.0, 1.0);
    }

    public JComponent createRawPanel(){
        rawArea = new JTextArea();
        rawArea.setEditable(false);
        rawArea.setWrapStyleWord(true);
        rawArea.setLineWrap(true);
        return new JScrollPane(rawArea);
    }

    public void setActiveInteraction(Interaction interaction){
        this.selectedInteraction = interaction;
        if(selectedInteraction == null){
            rawArea.setText(null);
            infoPanel.removeAll();
            infoPanel.add(noInteractionLabel, BorderLayout.CENTER);
            infoPanel.revalidate();
            infoPanel.repaint();
        }else {
            rawArea.setText(interaction.getOriginalObject().toString());
            infoPanel.removeAll();
            infoPanel.add(this.selectedInteraction.buildInteractionInfoPanel(), BorderLayout.CENTER);
            infoPanel.revalidate();
            infoPanel.repaint();
        }
    }
}
