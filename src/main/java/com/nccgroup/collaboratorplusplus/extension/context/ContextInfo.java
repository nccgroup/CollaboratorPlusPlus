package com.nccgroup.collaboratorplusplus.extension.context;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.awt.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

public class ContextInfo {

    String identifier;
    String collaboratorAddress;
    Date lastPolled;
    private ArrayList<UUID> interactionIds;
    private HashMap<UUID, Interaction> interactionEvents;
    boolean hasDNSEvent, hasHTTPEvent, hasSMTPEvent, hasHTTPSEvent, hasSMTPSEvent;

    Color highlight;
    transient ArrayList<UUID> recentInteractions;

    ContextInfo(String collaboratorAddress, String identifier){
        this.collaboratorAddress = collaboratorAddress;
        this.identifier = identifier;
        this.lastPolled = new Date();
        this.interactionIds = new ArrayList<>();
        this.interactionEvents = new HashMap<>();
        this.recentInteractions = new ArrayList<>();
    }

    public String getIdentifier() {
        return identifier;
    }

    public Date getLastPolled() {
        return lastPolled;
    }

    static ArrayList<Interaction> parseInteractions(ContextInfo contextInfo, JsonArray jsonArray){
        ArrayList<Interaction> interactions = new ArrayList<>();
        for (JsonElement jsonElement : jsonArray) {
            Interaction interaction = Interaction.parseFromJson(contextInfo, jsonElement.getAsJsonObject());
            if(interaction != null) interactions.add(interaction);
        }
        return interactions;
    }

    void addInteractions(ArrayList<Interaction> interactions){
        if(recentInteractions == null) recentInteractions = new ArrayList<>();
        for (Interaction interaction : interactions) {
            interactionIds.add(interaction.getUUID());
            interactionEvents.put(interaction.getUUID(), interaction);
            recentInteractions.add(interaction.getUUID());

            this.hasDNSEvent |= interaction.getInteractionType() == Interaction.InteractionType.DNS;
            this.hasHTTPEvent |= interaction.getInteractionType() == Interaction.InteractionType.HTTP;
            this.hasHTTPSEvent |= interaction.getInteractionType() == Interaction.InteractionType.HTTPS;
            this.hasSMTPEvent |= interaction.getInteractionType() == Interaction.InteractionType.SMTP;
            this.hasSMTPSEvent |= interaction.getInteractionType() == Interaction.InteractionType.SMTPS;
        }
    }

    public ArrayList<UUID> getRecentInteractions() {
        return recentInteractions;
    }

    public ArrayList<UUID> getInteractionIds() {
        return interactionIds;
    }

    public HashMap<UUID, Interaction> getInteractionEvents() {
        return interactionEvents;
    }

    public Interaction getEventAtIndex(int index){
        return this.interactionEvents.get(interactionIds.get(index));
    }

    public boolean hasDNSEvent() {
        return hasDNSEvent;
    }

    public boolean hasHTTPEvent() {
        return hasHTTPEvent;
    }

    public boolean hasSMTPEvent() {
        return hasSMTPEvent;
    }

    public boolean hasHTTPSEvent() {
        return hasHTTPSEvent;
    }

    public boolean hasSMTPSEvent(){
        return hasSMTPSEvent;
    }

    public Color getHighlight() {
        return highlight;
    }

    public String getCollaboratorAddress() {
        return this.collaboratorAddress;
    }
}
