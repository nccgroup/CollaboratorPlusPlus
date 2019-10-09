package com.nccgroup.collaboratorplusplus.extension.context;

import com.google.gson.*;
import org.apache.http.protocol.HTTP;

import java.lang.reflect.Type;

public class InteractionSerializer implements JsonDeserializer<Interaction>, JsonSerializer<Interaction> {
    @Override
    public Interaction deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        switch(((JsonObject) json).get("protocol").getAsString().toUpperCase()){
            case "DNS": return new DNSInteraction(json.getAsJsonObject());
            case "HTTP": return new HTTPInteraction(json.getAsJsonObject(), false);
            case "HTTPS": return new HTTPInteraction(json.getAsJsonObject(), true);
            case "SMTP": return new SMTPInteraction(json.getAsJsonObject(), false);
            case "SMTPS": return new SMTPInteraction(json.getAsJsonObject(), true);
        }
        return null;
    }

    @Override
    public JsonElement serialize(Interaction src, Type typeOfSrc, JsonSerializationContext context) {
        return src.getOriginalObject();
    }
}
