package com.nccgroup.collaboratorplusplus.extension.context;

import com.google.gson.*;

import java.lang.reflect.Type;

public class CollaboratorContextSerializer implements JsonDeserializer<CollaboratorContext>, JsonSerializer<CollaboratorContext> {
    @Override
    public CollaboratorContext deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        return null;
    }

    @Override
    public JsonElement serialize(CollaboratorContext src, Type typeOfSrc, JsonSerializationContext context) {
        return null;
    }
}
