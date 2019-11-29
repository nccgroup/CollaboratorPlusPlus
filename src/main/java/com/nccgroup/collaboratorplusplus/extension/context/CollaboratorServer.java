package com.nccgroup.collaboratorplusplus.extension.context;

import java.util.ArrayList;

public class CollaboratorServer {

    private final String collaboratorAddress;
    private final ArrayList<CollaboratorContext> contexts;
    int totalInteractions, dnsEventCount, httpEventCount, smtpEventCount, httpsEventCount, smtpsEventCount;

    public CollaboratorServer(String collaboratorAddress, ArrayList<CollaboratorContext> contexts){
        this.collaboratorAddress = collaboratorAddress;
        this.contexts = contexts;
    }

    public CollaboratorServer(String collaboratorAddress){
        this(collaboratorAddress, new ArrayList<>());
    }

    public String getCollaboratorAddress() {
        return collaboratorAddress;
    }

    public boolean contextExists(String identifier){
        return this.contexts.stream()
                .anyMatch(collaboratorContext -> collaboratorContext.getIdentifier().equalsIgnoreCase(identifier));
    }

    public void addContext(CollaboratorContext collaboratorContext){
        this.contexts.add(collaboratorContext);
    }

    public CollaboratorContext getContext(String identifier){
        return this.contexts.stream()
                .filter(collaboratorContext -> collaboratorContext.getIdentifier().equalsIgnoreCase(identifier))
                .findFirst().orElse(null);
    }

    public ArrayList<CollaboratorContext> getContexts() {
        return contexts;
    }

    public void removeContext(String identifier){
        this.contexts.removeIf(collaboratorContext -> collaboratorContext.getIdentifier().equalsIgnoreCase(identifier));
    }

    public void removeContext(CollaboratorContext collaboratorContext){
        this.contexts.remove(collaboratorContext);
        this.dnsEventCount -= collaboratorContext.dnsEventCount;
        this.httpEventCount -= collaboratorContext.httpEventCount;
        this.httpsEventCount -= collaboratorContext.httpsEventCount;
        this.smtpEventCount -= collaboratorContext.smtpEventCount;
        this.smtpsEventCount -= collaboratorContext.smtpsEventCount;
        this.totalInteractions -= collaboratorContext.getInteractionEvents().size();
    }

    public int getTotalInteractions() {
        return totalInteractions;
    }

    public int getDnsEventCount() {
        return dnsEventCount;
    }

    public int getHttpEventCount() {
        return httpEventCount;
    }

    public int getSmtpEventCount() {
        return smtpEventCount;
    }

    public int getHttpsEventCount() {
        return httpsEventCount;
    }

    public int getSmtpsEventCount() {
        return smtpsEventCount;
    }
}
