package com.nccgroup.collaboratorplusplus.extension.context;

import com.nccgroup.collaboratorplusplus.extension.CollaboratorEventListener;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.Globals;

import java.util.ArrayList;
import java.util.Date;

public class ContextManager {

    private final CollaboratorPlusPlus extension;
    private ArrayList<CollaboratorServer> collaboratorServers;
    private final ArrayList<CollaboratorEventListener> eventListeners;

    public ContextManager(CollaboratorPlusPlus extension){
        this.extension = extension;
        this.collaboratorServers = new ArrayList<>();
        this.eventListeners = new ArrayList<>();
        loadState();
    }

    public void pollingRequestSent(String collaboratorAddress, String contextIdentifier){
        CollaboratorServer collaboratorServer = getCollaboratorServer(collaboratorAddress);
        if(collaboratorServer == null){
            collaboratorServer = new CollaboratorServer(collaboratorAddress);
            int index = collaboratorServers.size();
            collaboratorServers.add(collaboratorServer);

            for (CollaboratorEventListener listener : this.eventListeners) {
                try{
                    listener.onCollaboratorServerRegistered(collaboratorServer, index);
                }catch (Exception e){}
            }
        }

        CollaboratorContext collaboratorContext = collaboratorServer.getContext(contextIdentifier);

        if(collaboratorContext == null){
            collaboratorContext = new CollaboratorContext(collaboratorServer, contextIdentifier);
            int index = collaboratorServer.getContexts().size();
            collaboratorServer.addContext(collaboratorContext);

            for (CollaboratorEventListener eventListener : eventListeners) {
                try {
                    eventListener.onCollaboratorContextRegistered(collaboratorContext, index);
                }catch (Exception ignored){ }
            }
        }

        collaboratorContext.lastPolled = new Date();

        saveState();

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingRequestSent(collaboratorContext);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public void addInteractions(String collaboratorAddress, String contextIdentifier, ArrayList<Interaction> interactions){

        CollaboratorServer collaboratorServer = getCollaboratorServer(collaboratorAddress);
        CollaboratorContext collaboratorContext = collaboratorServer.getContext(contextIdentifier);

        collaboratorContext.addInteractions(interactions);

        saveState();

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingResponseReceived(collaboratorContext, interactions);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public void pollingFailure(String collaboratorAddress, String contextIdentifier, String message){

        CollaboratorServer collaboratorServer = getCollaboratorServer(collaboratorAddress);
        CollaboratorContext context = collaboratorServer.getContext(contextIdentifier);

        for (CollaboratorEventListener eventListener : eventListeners) {
            try {
                eventListener.onPollingFailure(context, message);
            }catch (Exception ignored){
                ignored.printStackTrace();
            }
        }
    }

    public ArrayList<Interaction> requestInteractions(CollaboratorContext context) throws Exception {
        if(extension.getProxyService() == null) throw new Exception("The collaborator proxy is not running.");
        return  extension.getProxyService().requestInteractionsForContext(context);
    }

    public void removeCollaboratorContext(CollaboratorContext context){
        int index = context.getCollaboratorServer().getContexts().indexOf(context);
        if(index == -1) return;
        context.getCollaboratorServer().removeContext(context);
        saveState();
        for (CollaboratorEventListener eventListener : eventListeners) {
            try{
                eventListener.onCollaboratorContextRemoved(context, index);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void removeCollaboratorServer(CollaboratorServer server){
        int index = this.collaboratorServers.indexOf(server);
        if(index == -1) return;
        this.collaboratorServers.remove(server);
        saveState();
        for (CollaboratorEventListener eventListener : eventListeners) {
            try{
                eventListener.onCollaboratorServerRemoved(server, index);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
    }

    public void saveState(){
        this.extension.getPreferences().setSetting(Globals.PREF_COLLABORATOR_HISTORY, collaboratorServers);
    }

    public boolean hasCollaboratorServer(String collaboratorAddress){
        return collaboratorServers.stream()
                .anyMatch(collaboratorServer ->
                        collaboratorServer.getCollaboratorAddress().equalsIgnoreCase(collaboratorAddress)
                );
    }

    public CollaboratorServer getCollaboratorServer(String collaboratorAddress){
        return collaboratorServers.stream()
                .filter(collaboratorServer -> collaboratorServer.getCollaboratorAddress().equalsIgnoreCase(collaboratorAddress))
                .findFirst().orElse(null);
    }

    public ArrayList<CollaboratorServer> getCollaboratorServers(){
        return this.collaboratorServers;
    }

    public void addEventListener(CollaboratorEventListener listener){
        this.eventListeners.add(listener);
    }

    public void removeEventListener(CollaboratorEventListener listener){
        this.eventListeners.remove(listener);
    }

    private void loadState(){
        this.collaboratorServers = this.extension.getPreferences().getSetting(Globals.PREF_COLLABORATOR_HISTORY);
    }
}
