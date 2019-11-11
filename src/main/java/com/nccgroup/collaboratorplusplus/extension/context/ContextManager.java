package com.nccgroup.collaboratorplusplus.extension.context;

import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventListener;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.Globals;

import java.awt.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

public class ContextManager {

    private final CollaboratorPlusPlus extension;
    private ArrayList<String> identifiers;
    private HashMap<String, ContextInfo> collaboratorHistory;
    private final ArrayList<CollaboratorEventListener> eventListeners;

    public ContextManager(CollaboratorPlusPlus extension){
        this.extension = extension;
        this.identifiers = new ArrayList<>();
        this.eventListeners = new ArrayList<>();
        loadCollaboratorContextHistory();
    }

    public void pollingRequestSent(String collaboratorAddress, String contextIdentifier){
        String completeIdentifier = getCompleteIdentifier(collaboratorAddress, contextIdentifier);

        boolean isFirstPoll = !this.collaboratorHistory.containsKey(completeIdentifier);
        if(isFirstPoll){
            this.collaboratorHistory.put(completeIdentifier, new ContextInfo(collaboratorAddress, contextIdentifier));
            this.identifiers.add(completeIdentifier);
        }else{
            this.collaboratorHistory.get(completeIdentifier).lastPolled = new Date();
        }

        saveState();

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingRequestSent(collaboratorAddress, contextIdentifier, isFirstPoll);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public void addInteractions(String collaboratorAddress, String identifier, ArrayList<Interaction> interactions){
        String completeIdentifier = getCompleteIdentifier(collaboratorAddress, identifier);
        if(!this.collaboratorHistory.containsKey(completeIdentifier)){
            this.collaboratorHistory.put(completeIdentifier, new ContextInfo(collaboratorAddress, identifier));
            this.identifiers.add(completeIdentifier);
        }

        //Parse our interactions
        ContextInfo contextInfo = this.collaboratorHistory.get(completeIdentifier);
        contextInfo.addInteractions(interactions);

        saveState();

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingResponseReceived(collaboratorAddress, identifier, interactions);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public void pollingFailure(String collaboratorAddress, String identifier, String message){
        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingFailure(collaboratorAddress, identifier, message);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public ArrayList<Interaction> requestInteractions(String identifier) throws Exception {
        if(extension.getProxyService() == null) throw new Exception("The collaborator proxy is not running.");
        return  extension.getProxyService().requestInteractionsForContext(identifier);
    }

    public void saveState(){
        this.extension.getPreferences().setSetting(Globals.PREF_COLLABORATOR_HISTORY, collaboratorHistory);
    }

    public HashMap<String, ContextInfo> getCollaboratorContexts(){
        return this.collaboratorHistory;
    }

    public ContextInfo getCollaboratorContext(String identifier){
        return this.collaboratorHistory.get(identifier);
    }

    public ArrayList<String> getIdentifiers(){
        return this.identifiers;
    }

    public void addEventListener(CollaboratorEventListener listener){
        this.eventListeners.add(listener);
    }

    public void removeEventListener(CollaboratorEventListener listener){
        this.eventListeners.remove(listener);
    }

    private void loadCollaboratorContextHistory(){
        this.collaboratorHistory = this.extension.getPreferences().getSetting(Globals.PREF_COLLABORATOR_HISTORY);
        this.identifiers.addAll(this.collaboratorHistory.keySet());
    }

    public void deleteContext(ContextInfo contextInfo) {
        this.identifiers.remove(contextInfo.getIdentifier());
        this.collaboratorHistory.remove(contextInfo.getIdentifier());
        saveState();
    }

    public void setHighlight(ContextInfo contextInfo, Color color){
        contextInfo.highlight = color;
        saveState();
    }

    private static String getCompleteIdentifier(String collaboratorAddress, String identifier){
        return String.format("%s.%s", identifier, collaboratorAddress);
    }

}
