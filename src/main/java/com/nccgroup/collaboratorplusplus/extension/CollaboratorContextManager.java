package com.nccgroup.collaboratorplusplus.extension;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.util.EntityUtils;

import java.util.*;

public class CollaboratorContextManager {

    private final CollaboratorPlusPlus extension;
    private ArrayList<String> identifiers;
    private HashMap<String, ContextInfo> collaboratorHistory;
    private final ArrayList<CollaboratorEventListener> eventListeners;

    public CollaboratorContextManager(CollaboratorPlusPlus extension){
        this.extension = extension;
        this.identifiers = new ArrayList<>();
        this.eventListeners = new ArrayList<>();
        loadCollaboratorContextHistory();
    }

    public void pollingRequestSent(String identifier){
        boolean isFirstPoll = !this.collaboratorHistory.containsKey(identifier);
        if(isFirstPoll){
            this.collaboratorHistory.put(identifier, new ContextInfo(identifier));
            this.identifiers.add(identifier);
        }else{
            this.collaboratorHistory.get(identifier).lastPolled = new Date();
        }

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingRequestSent(identifier, isFirstPoll);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public void interactionEventsReceived(String identifier, JsonArray interactions){
        if(!this.collaboratorHistory.containsKey(identifier)){
            this.collaboratorHistory.put(identifier, new ContextInfo(identifier));
            this.identifiers.add(identifier);
        }

        this.collaboratorHistory.get(identifier).interactionEvents.addAll(interactions);
        this.extension.getPreferences().setSetting(Globals.PREF_COLLABORATOR_HISTORY, collaboratorHistory);

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingResponseRecieved(identifier, interactions);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public JsonArray requestInteractions(String identifier) throws Exception {
        if(extension.getProxyService() == null) throw new Exception("The collaborator proxy is not running.");

        HttpResponse response = extension.getProxyService().requestInteractionsForContext(identifier);
        if(response.getStatusLine().getStatusCode() == HttpStatus.SC_OK){
            String responseString = EntityUtils.toString(response.getEntity());
            JsonObject responseJson = new JsonParser().parse(responseString).getAsJsonObject();
            if(responseJson.has("responses"))
                return responseJson.getAsJsonArray( "responses");
            else
                return new JsonArray();
        }
        return null;
    }

    public HashMap<String, ContextInfo> getCollaboratorHistory(){
        return this.collaboratorHistory;
    }

    public ContextInfo getInteractions(String identifier){
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

    public static class ContextInfo {
        String identifier;
        Date lastPolled;
        JsonArray interactionEvents;

        private ContextInfo(String identifier){
            this.identifier = identifier;
            this.lastPolled = new Date();
            interactionEvents = new JsonArray();
        }

        public String getIdentifier() {
            return identifier;
        }

        public Date getLastPolled() {
            return lastPolled;
        }

        public JsonArray getInteractionEvents() {
            return interactionEvents;
        }
    }

}
