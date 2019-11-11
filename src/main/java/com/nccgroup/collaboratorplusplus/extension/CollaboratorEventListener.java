package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import java.util.ArrayList;

public interface CollaboratorEventListener {
    void onPollingRequestSent(String collaboratorServer, String contextIdentifier, boolean isFirstPoll);
    void onPollingResponseReceived(String collaboratorServer, String contextIdentifier, ArrayList<Interaction> interactions);
    void onPollingFailure(String collaboratorServer, String contextIdentifier, String error);
}
