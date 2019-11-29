package com.nccgroup.collaboratorplusplus.extension.context;

import java.awt.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;

public class CollaboratorContext {

    transient CollaboratorServer collaboratorServer;
    String identifier;
    Date lastPolled;
    private ArrayList<UUID> interactionIds;
    private HashMap<UUID, Interaction> interactionEvents;
    int dnsEventCount, httpEventCount, smtpEventCount, httpsEventCount, smtpsEventCount;

    Color highlight;
    transient ArrayList<UUID> recentInteractions;

    CollaboratorContext(String identifier){
        this.identifier = identifier;
        this.lastPolled = new Date();
        this.interactionIds = new ArrayList<>();
        this.interactionEvents = new HashMap<>();
        this.recentInteractions = new ArrayList<>();
    }

    CollaboratorContext(CollaboratorServer collaboratorServer, String identifier){
        this(identifier);
        this.collaboratorServer = collaboratorServer;
    }

    public String getIdentifier() {
        return identifier;
    }

    public Date getLastPolled() {
        return lastPolled;
    }

    void addInteractions(ArrayList<Interaction> interactions){
        if(recentInteractions == null) recentInteractions = new ArrayList<>();
        for (Interaction interaction : interactions) {
            interactionIds.add(interaction.getUUID());
            interactionEvents.put(interaction.getUUID(), interaction);
            recentInteractions.add(interaction.getUUID());

            if(this.collaboratorServer != null)
                this.collaboratorServer.totalInteractions++;

            //Update context interaction counts
            switch (interaction.getInteractionType()){
                case DNS: {
                    this.dnsEventCount++;
                    if(this.collaboratorServer != null)
                        this.collaboratorServer.dnsEventCount++;
                    break;
                }
                case HTTP: {
                    this.httpEventCount++;
                    if(this.collaboratorServer != null)
                        this.collaboratorServer.httpEventCount++;
                    break;
                }
                case HTTPS: {
                    this.httpsEventCount++;
                    if(this.collaboratorServer != null)
                        this.collaboratorServer.httpsEventCount++;
                    break;
                }
                case SMTP: {
                    this.smtpEventCount++;
                    if(this.collaboratorServer != null)
                        this.collaboratorServer.smtpEventCount++;
                    break;
                }
                case SMTPS: {
                    this.smtpsEventCount++;
                    if(this.collaboratorServer != null)
                        this.collaboratorServer.smtpsEventCount++;
                    break;
                }
            }
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

    public int getDNSInteractionCount() {
        return dnsEventCount;
    }

    public int getHttpInteractionCount() {
        return httpEventCount;
    }

    public int getSMTPInteractionCount() {
        return smtpEventCount;
    }

    public int getHttpsInteractionCount() {
        return httpsEventCount;
    }

    public int getSMTPSInteractionCount(){
        return smtpsEventCount;
    }

    public Color getHighlight() {
        return highlight;
    }

    public CollaboratorServer getCollaboratorServer(){
        return this.collaboratorServer;
    }

    public void setCollaboratorServer(CollaboratorServer collaboratorServer) {
        this.collaboratorServer = collaboratorServer;
    }
}
