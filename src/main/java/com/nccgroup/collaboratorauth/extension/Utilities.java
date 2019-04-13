package com.nccgroup.collaboratorauth.extension;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.logController;
import static com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator.callbacks;
import static com.nccgroup.collaboratorauth.extension.Globals.*;

public class Utilities {

    public static void blockPublicCollaborator(){
        String stringConfig = callbacks.saveConfigAsJson(HOSTNAME_RESOLUTION_CONFIG_PATH);
        JsonObject config = new JsonParser().parse(stringConfig).getAsJsonObject();
        JsonArray resolutionElements = config.getAsJsonObject("project_options")
                                             .getAsJsonObject("connections")
                                             .getAsJsonArray("hostname_resolution");

        boolean shouldAddEntry = true;
        if(resolutionElements.size() > 0){
            for (JsonElement resolutionElement : resolutionElements) {
                String hostname = resolutionElement.getAsJsonObject().get("hostname").getAsString();
                String ip = resolutionElement.getAsJsonObject().get("ip_address").getAsString();
                Boolean enabled = resolutionElement.getAsJsonObject().get("enabled").getAsBoolean();

                if(hostname.equalsIgnoreCase(PUBLIC_COLLABORATOR_HOSTNAME)){
                    if(ip.equalsIgnoreCase("127.0.0.1")){
                        //Existing entry, just make sure its enabled.
                        if(enabled){
                            logController.logInfo("Sink for public collaborator server already exists, continuing...");
                        }else {
                            logController.logInfo("Enabling sink for public collaborator server.");
                            resolutionElement.getAsJsonObject().addProperty("enabled", true);
                        }
                        shouldAddEntry = false;
                    }else{
                        //Not our entry,
                        logController.logInfo("Hostname resolution entry exists for public collaborator server. Disabling and adding sink entry.");
                        resolutionElement.getAsJsonObject().addProperty("enabled", false);
                    }
                    break;
                }
            }
        }else{
            logController.logInfo("Adding sink for the public collaborator server (just in case).");
        }
        if(shouldAddEntry){
            resolutionElements.add(buildPublicCollaboratorSink());
            callbacks.loadConfigFromJson(config.toString());
        }
    }

    public static void unblockPublicCollaborator(){
        String stringConfig = callbacks.saveConfigAsJson(HOSTNAME_RESOLUTION_CONFIG_PATH);
        JsonObject config = new JsonParser().parse(stringConfig).getAsJsonObject();
        JsonArray resolutionElements = config.getAsJsonObject("project_options")
                                             .getAsJsonObject("connections")
                                             .getAsJsonArray("hostname_resolution");

        for (JsonElement resolutionElement : resolutionElements) {
            String hostname = resolutionElement.getAsJsonObject().get("hostname").getAsString();
            String ip = resolutionElement.getAsJsonObject().get("ip_address").getAsString();
            Boolean enabled = resolutionElement.getAsJsonObject().get("enabled").getAsBoolean();
            if(hostname.equalsIgnoreCase(PUBLIC_COLLABORATOR_HOSTNAME) && ip.equalsIgnoreCase("127.0.0.1")){
                resolutionElement.getAsJsonObject().addProperty("enabled", false);
                logController.logInfo("Disabled sink for public collaborator server.");
                break;
            }
        }

        callbacks.loadConfigFromJson(config.toString());
    }

    private static JsonObject buildPublicCollaboratorSink(){
        JsonObject entry = new JsonObject();
        entry.addProperty("enabled", true);
        entry.addProperty("hostname", PUBLIC_COLLABORATOR_HOSTNAME);
        entry.addProperty("ip_address", "127.0.0.1");
        return entry;
    }
}
