package com.nccgroup.collaboratorplusplus.utilities;

import com.google.gson.*;
import org.apache.logging.log4j.Level;

import java.lang.reflect.Type;

public class LevelSerializer implements JsonDeserializer<Level> {

    @Override
    public Level deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        return Level.valueOf(json.getAsJsonObject().get("name").getAsString());
    }
}
