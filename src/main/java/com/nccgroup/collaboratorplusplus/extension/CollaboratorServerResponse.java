package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.Interaction;
import org.apache.http.Header;
import org.apache.http.HttpResponse;

import java.util.ArrayList;

public class CollaboratorServerResponse {
    private HttpResponse httpResponse;
    private ArrayList<Interaction> interactions;

    public CollaboratorServerResponse(HttpResponse response, ArrayList<Interaction> interactions){
        this.httpResponse = response;
        this.interactions = interactions;
    }

    public ArrayList<Interaction> getInteractions() {
        return interactions;
    }

    public HttpResponse getHttpResponse() {
        return httpResponse;
    }
}
