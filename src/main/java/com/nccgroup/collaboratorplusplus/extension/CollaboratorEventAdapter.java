package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import java.util.ArrayList;

public abstract class CollaboratorEventAdapter implements CollaboratorEventListener {

    @Override
    public void onPollingRequestSent(String collaboratorServer, String contextIdentifier, boolean isFirstPoll) {}

    @Override
    public void onPollingResponseReceived(String collaboratorServer, String contextIdentifier, ArrayList<Interaction> interactions) {}

    @Override
    public void onPollingFailure(String collaboratorServer, String contextIdentifier, String error) {}
}
