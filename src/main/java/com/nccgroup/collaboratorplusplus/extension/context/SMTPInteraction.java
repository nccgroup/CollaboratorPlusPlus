package com.nccgroup.collaboratorplusplus.extension.context;

import burp.IMessageEditor;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.utilities.SelectableLabel;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class SMTPInteraction extends Interaction{

    String sender;
    ArrayList<String> recipients;
    String message;
    String conversation;

    protected SMTPInteraction(JsonObject interaction, boolean isSSL) {
        this(null, interaction, isSSL);
    }

    protected SMTPInteraction(ContextInfo context, JsonObject interaction, boolean isSSL) {
        super(context, isSSL ? InteractionType.SMTPS : InteractionType.SMTP, interaction);

        //Parse SMTP specific properties here
        sender = new String(Base64.decode(interaction.getAsJsonObject("data").get("sender").getAsString()));
        message = new String(Base64.decode(interaction.getAsJsonObject("data").get("message").getAsString()));
        conversation = new String(Base64.decode(interaction.getAsJsonObject("data").get("conversation").getAsString()));
        recipients = new ArrayList<>();
        for (JsonElement jsonElement : interaction.getAsJsonObject("data").get("recipients").getAsJsonArray()) {
            String recipient = new String(Base64.decode(jsonElement.getAsString()));
            recipients.add(recipient);
        }
    }

    public String getSender() {
        return sender;
    }

    public ArrayList<String> getRecipients() {
        return recipients;
    }

    public String getMessage() {
        return message;
    }

    public String getConversation() {
        return conversation;
    }

    @Override
    public JComponent buildInteractionInfoPanel() {
        JComponent basePanel = super.buildInteractionInfoPanel();
        IMessageEditor editor = CollaboratorPlusPlus.callbacks.createMessageEditor(null, false);
        editor.setMessage(this.conversation.getBytes(), true);

        return new PanelBuilder(null).build(new Component[][]{
                new Component[]{basePanel, basePanel},
                new Component[]{new JSeparator(JSeparator.HORIZONTAL), new JSeparator(JSeparator.HORIZONTAL)},
                new Component[]{new JLabel("Sender:  "), new SelectableLabel(sender)},
                new Component[]{new JLabel("Recipients:  "), new SelectableLabel(this.recipients.stream().collect(Collectors.joining("; ")))},
                new Component[]{editor.getComponent(), editor.getComponent()},
        }, new int[][]{
                new int[]{0, 0},
                new int[]{0, 0},
                new int[]{0, 0},
                new int[]{0, 1},
                new int[]{0, 999},
        }, Alignment.FILL, 1.0, 1.0);
    }
}
