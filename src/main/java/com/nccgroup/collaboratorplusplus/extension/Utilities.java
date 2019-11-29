package com.nccgroup.collaboratorplusplus.extension;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import org.apache.http.HttpHost;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.Inet4Address;
import java.util.ArrayList;

import static com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus.callbacks;
import static com.nccgroup.collaboratorplusplus.extension.Globals.*;

public class Utilities {

    private static final Logger logger = LogManager.getLogger(Utilities.class);

    public static ArrayList<Interaction> parseInteractions(JsonObject collaboratorResponse){
        ArrayList<Interaction> interactions = new ArrayList<>();
        if(collaboratorResponse.has("responses")) {
            JsonArray jsonArray = collaboratorResponse.get("responses").getAsJsonArray();
            for (JsonElement jsonElement : jsonArray) {
                Interaction interaction = Interaction.parseFromJson(jsonElement.getAsJsonObject());
                if (interaction != null) interactions.add(interaction);
            }
        }
        return interactions;
    }

    public static JsonObject convertInteractionsToCollaboratorResponse(ArrayList<Interaction> interactions){
        JsonObject json = new JsonObject();
        JsonArray interactionArray = new JsonArray(interactions.size());
        for (Interaction interaction : interactions) {
            interactionArray.add(interaction.getOriginalObject());
        }
        json.add("responses", interactionArray);
        return json;
    }

    public static ArrayList<Interaction> parseInteractions(CollaboratorContext collaboratorContext, JsonArray jsonArray){
        ArrayList<Interaction> interactions = new ArrayList<>();
        for (JsonElement jsonElement : jsonArray) {
            Interaction interaction = Interaction.parseFromJson(collaboratorContext, jsonElement.getAsJsonObject());
            if(interaction != null) interactions.add(interaction);
        }
        return interactions;
    }

    public static HttpHost getBurpProxyHost(String scheme) {
        String configString = callbacks.saveConfigAsJson("proxy.request_listeners");
        JsonObject config = new JsonParser().parse(configString).getAsJsonObject();
        JsonArray listeners = config.getAsJsonObject("proxy").getAsJsonArray("request_listeners");
        for (JsonElement listener : listeners) {
            JsonObject listnerObject = (JsonObject) listener;
            if(listnerObject.get("running").getAsBoolean()){
                int port = listnerObject.get("listener_port").getAsInt();
                String listenMode = listnerObject.get("listen_mode").getAsString();
                if(listenMode.equals("loopback_only")){
                    return new HttpHost("127.0.0.1", port, scheme);
                }
                if(listenMode.equals("all_interfaces")){
                    return new HttpHost("0.0.0.0", port, scheme);
                }
                if(listenMode.equals("specific_address")){
                    String address = listnerObject.get("listen_specific_address").getAsString();
                    return new HttpHost(address, port, scheme);
                }
            }
        }
        return null;
    }

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
                            logger.info("Sink for public collaborator server already exists, continuing...");
                        }else {
                            logger.info("Enabling sink for public collaborator server.");
                            resolutionElement.getAsJsonObject().addProperty("enabled", true);
                        }
                        shouldAddEntry = false;
                    }else{
                        //Not our entry,
                        logger.info("Hostname resolution entry exists for public collaborator server. Disabling and adding sink entry.");
                        resolutionElement.getAsJsonObject().addProperty("enabled", false);
                    }
                    break;
                }
            }
        }else{
            logger.info("Adding DNS sink for the public collaborator server: \"burpcollaborator.net\" .");
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
                logger.info("Disabled sink for public collaborator server.");
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

    public static void backupCollaboratorConfig(Preferences preferences){
        String config = callbacks.saveConfigAsJson(COLLABORATOR_SERVER_CONFIG_PATH);
        preferences.setSetting(PREF_ORIGINAL_COLLABORATOR_SETTINGS, config);
    }

    public static void restoreCollaboratorConfig(Preferences preferences){
        String config = preferences.getSetting(PREF_ORIGINAL_COLLABORATOR_SETTINGS);
        callbacks.loadConfigFromJson(config);
    }

    public static String buildPollingRedirectionConfig(Preferences preferences, int listenPort){
        return "{\"project_options\": {\"misc\": {\"collaborator_server\": " +
                "{\"location\": \"" + preferences.getSetting(PREF_COLLABORATOR_ADDRESS) + "\"," +
                "\"polling_location\": \"" + Inet4Address.getLoopbackAddress().getHostName() + ":" + listenPort + "\"," +
                "\"poll_over_unencrypted_http\": \"true\"," +
                "\"type\": \"private\"" +
                "}}}}";
    }
}
