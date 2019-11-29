package com.nccgroup.collaboratorplusplus.extension.context;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.google.gson.JsonObject;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.utilities.StaticHTTPMessageController;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;

public class HTTPInteraction extends Interaction{

    byte[] request;
    byte[] response;

    protected HTTPInteraction(JsonObject interaction, boolean isHttps) {
        this(null, interaction, isHttps);
    }

    protected HTTPInteraction(CollaboratorContext context, JsonObject interaction, boolean isHttps) {
        super(context, isHttps ? InteractionType.HTTPS : InteractionType.HTTP, interaction);

        //Parse HTTP specific properties here
        this.request = Base64.decode(interaction.getAsJsonObject("data").get("request").getAsString());
        this.response = Base64.decode(interaction.getAsJsonObject("data").get("response").getAsString());
    }

    @Override
    public JComponent buildInteractionInfoPanel() {
        JComponent basePanel = super.buildInteractionInfoPanel();
        StaticHTTPMessageController messageController =
                new StaticHTTPMessageController(CollaboratorPlusPlus.callbacks, buildInteractionURL(), this.request, this.response);

        JSplitPane requestResponseViewer = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                messageController.buildRequestViewer().getComponent(),
                messageController.buildResponseViewer().getComponent());
        requestResponseViewer.setResizeWeight(0.5);

        return new PanelBuilder(null).build(new Component[][]{
                new Component[]{basePanel},
                new Component[]{requestResponseViewer}
        }, new int[][]{
                new int[]{0},
                new int[]{1}
        }, Alignment.FILL, 1.0, 1.0);
    }

    private URL buildInteractionURL() {
        try {
            return new URL(this.interactionType.toString(), this.interactionString +
                            (this.context != null ? this.context.getCollaboratorServer().getCollaboratorAddress() : ""),
                    this.interactionType == InteractionType.HTTPS ? 443 : 80, "");
        } catch (MalformedURLException e) {
            return null;
        }
    }
}
