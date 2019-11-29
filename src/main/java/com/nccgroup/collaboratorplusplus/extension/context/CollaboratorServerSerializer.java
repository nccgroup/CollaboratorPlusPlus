package com.nccgroup.collaboratorplusplus.extension.context;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.ArrayList;

public class CollaboratorServerSerializer implements JsonDeserializer<CollaboratorServer>, JsonSerializer<CollaboratorServer> {
    @Override
    public CollaboratorServer deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext deserializationContext) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();
        String collaboratorAddress = jsonObject.get("serverAddress").getAsString();
        CollaboratorServer collaboratorServer = new CollaboratorServer(collaboratorAddress);
        collaboratorServer.totalInteractions = jsonObject.get("totalInteractions").getAsInt();
        collaboratorServer.dnsEventCount = jsonObject.get("dnsInteractions").getAsInt();
        collaboratorServer.httpEventCount = jsonObject.get("httpInteractions").getAsInt();
        collaboratorServer.httpsEventCount = jsonObject.get("httpsInteractions").getAsInt();
        collaboratorServer.smtpEventCount = jsonObject.get("smtpInteractions").getAsInt();
        collaboratorServer.smtpsEventCount = jsonObject.get("smtpsInteractions").getAsInt();

        for (JsonElement context : jsonObject.getAsJsonArray("contexts")) {
            CollaboratorContext collaboratorContext = deserializationContext.deserialize(context, CollaboratorContext.class);
            collaboratorContext.setCollaboratorServer(collaboratorServer);
            collaboratorServer.addContext(collaboratorContext);
        }

        return collaboratorServer;
    }

    @Override
    public JsonElement serialize(CollaboratorServer src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject obj = new JsonObject();
        obj.addProperty("serverAddress", src.getCollaboratorAddress());
        obj.addProperty("totalInteractions", src.getTotalInteractions());
        obj.addProperty("dnsInteractions", src.getDnsEventCount());
        obj.addProperty("httpInteractions", src.getHttpEventCount());
        obj.addProperty("httpsInteractions", src.getHttpsEventCount());
        obj.addProperty("smtpInteractions", src.getSmtpEventCount());
        obj.addProperty("smtpsInteractions", src.getSmtpsEventCount());
        JsonArray contexts = new JsonArray();
        for (CollaboratorContext collaboratorContext : src.getContexts()) {
            contexts.add(context.serialize(collaboratorContext, CollaboratorContext.class));
        }
        obj.add("contexts", contexts);
        return obj;
    }
}
