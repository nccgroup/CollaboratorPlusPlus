package com.nccgroup.collaboratorplusplus.extension.context;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.nccgroup.collaboratorplusplus.utilities.SelectableLabel;

import javax.swing.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Date;
import java.util.UUID;

public abstract class Interaction {
    public enum InteractionType {SMTP, SMTPS, HTTP, HTTPS, DNS}

    private final UUID identifier;
    protected InteractionType interactionType;
    protected transient ContextInfo context;
    protected String interactionString;
    protected long time;
    protected String client;
    protected String clientPart;
    protected String opCode;
    protected JsonObject originalObject;

    private Interaction(){
        this.identifier = UUID.randomUUID();
    }

    protected Interaction(ContextInfo context, InteractionType type, JsonObject interaction){
        this();
        this.interactionType = type;
        this.context = context;

        //Parse our info from the jsonObject
        this.interactionString = interaction.get("interactionString").getAsString();
        this.time = interaction.get("time").getAsLong();
        this.client = interaction.get("client").getAsString();
        this.clientPart = interaction.get("clientPart").getAsString();
        this.opCode = interaction.get("opCode").getAsString();
        this.originalObject = interaction;
    }

    public UUID getUUID() {
        return identifier;
    }

    public InteractionType getInteractionType(){
        return this.interactionType;
    }

    public String getInteractionString() {
        return interactionString;
    }

    public long getTime() {
        return time;
    }

    public String getClient() {
        return client;
    }

    public JsonObject getOriginalObject() {
        return originalObject;
    }

    public String getInteractionStringWithDomain(){
        if(this.context != null) return String.format("%s.%s", this.interactionString, context.getCollaboratorAddress());
        else return this.interactionString;
    }

    @Override
    public String toString() {
        return originalObject.toString();
    }

    public JComponent buildInteractionInfoPanel(){
        return new PanelBuilder(null).build(new JComponent[][]{
                new JComponent[]{new JLabel("Type:   "), new JLabel(this.interactionType.toString())},
                new JComponent[]{new JLabel("Interaction String:   "), new SelectableLabel(getInteractionStringWithDomain())},
                new JComponent[]{new JLabel("Client:   "), new JLabel(this.client)},
                new JComponent[]{new JLabel("Time:   "), new JLabel(new Date(this.time).toString())},
        }, new int[][]{
                new int[]{0, 100},
                new int[]{0, 100},
                new int[]{0, 100},
                new int[]{0, 100}
        }, Alignment.TOPLEFT, 1.0, 0.0);
    }

    public static Interaction parseFromJson(ContextInfo contextInfo, JsonObject json){
        switch(json.getAsJsonObject().get("protocol").getAsString().toUpperCase()){
            case "DNS": return new DNSInteraction(contextInfo, json);
            case "HTTP": return new HTTPInteraction(contextInfo, json, false);
            case "HTTPS": return new HTTPInteraction(contextInfo, json, true);
            case "SMTP": return new SMTPInteraction(contextInfo, json, false);
            case "SMTPS": return new SMTPInteraction(contextInfo, json, true);
        }
        return null;
    }

    public static Interaction parseFromJson(JsonObject json){
        switch(json.getAsJsonObject().get("protocol").getAsString().toUpperCase()){
            case "DNS": return new DNSInteraction(json);
            case "HTTP": return new HTTPInteraction(json, false);
            case "HTTPS": return new HTTPInteraction(json, true);
            case "SMTP": return new SMTPInteraction(json, false);
            case "SMTPS": return new SMTPInteraction(json, true);
        }
        return null;
    }
}
