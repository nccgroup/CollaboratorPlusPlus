package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import java.util.ArrayList;

public abstract class CollaboratorEventAdapter implements CollaboratorEventListener {

    @Override
    public void onPollingRequestSent(String biid, boolean isFirstPoll) {}

    @Override
    public void onPollingResponseReceived(String biid, ArrayList<Interaction> interactions) {}

    @Override
    public void onPollingFailure(String error) {}
}
