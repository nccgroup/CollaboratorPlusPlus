package com.nccgroup.collaboratorplusplus.extension.context;

import burp.IMessageEditor;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.google.gson.JsonObject;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.utilities.SelectableLabel;
import com.nccgroup.collaboratorplusplus.utilities.StaticHTTPMessageController;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.awt.*;
import java.net.URL;

public class DNSInteraction extends Interaction {

    String subDomain;
    byte[] rawRequest;
    int type;

    DNSInteraction(JsonObject interaction){
        this(null, interaction);
    }

    DNSInteraction(ContextInfo context, JsonObject interaction){
        super(context, InteractionType.DNS, interaction);

        //Parse DNS specific properties here
        this.subDomain = interaction.getAsJsonObject("data").get("subDomain").getAsString();
        this.rawRequest = Base64.decode(interaction.getAsJsonObject("data").get("rawRequest").getAsString());
        this.type = interaction.getAsJsonObject("data").get("type").getAsInt();
    }

    @Override
    public JComponent buildInteractionInfoPanel() {
        JComponent basePanel = super.buildInteractionInfoPanel();
        IMessageEditor editor = CollaboratorPlusPlus.callbacks.createMessageEditor(null, false);
        editor.setMessage(this.rawRequest, true);

        JScrollPane subdomainPane = new JScrollPane(new SelectableLabel(this.subDomain));
        subdomainPane.setBorder(null);
        subdomainPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        subdomainPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        subdomainPane.setMinimumSize(new Dimension(subdomainPane.getWidth(), 40));
        return new PanelBuilder(null).build(new Component[][]{
                new Component[]{basePanel, basePanel},
                new Component[]{new JSeparator(JSeparator.HORIZONTAL), new JSeparator(JSeparator.HORIZONTAL)},
                new Component[]{new JLabel("SubDomain:  "), subdomainPane},
                new Component[]{new JLabel("Type:  "), new SelectableLabel(String.valueOf(this.type))},
                new Component[]{editor.getComponent(), editor.getComponent()},
        }, new int[][]{
                new int[]{0, 0},
                new int[]{0, 0},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 999},
        }, Alignment.FILL, 1.0, 1.0);
    }
}
