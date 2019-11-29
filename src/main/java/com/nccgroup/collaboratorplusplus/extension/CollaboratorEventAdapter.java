package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorServer;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import java.util.ArrayList;

public abstract class CollaboratorEventAdapter implements CollaboratorEventListener {

    @Override
    public void onCollaboratorServerRegistered(CollaboratorServer collaboratorServer, int index) {}

    @Override
    public void onCollaboratorServerRemoved(CollaboratorServer collaboratorServer, int index) {}

    @Override
    public void onCollaboratorContextRegistered(CollaboratorContext collaboratorContext, int index) {}

    @Override
    public void onCollaboratorContextRemoved(CollaboratorContext collaboratorContext, int index) {}

    @Override
    public void onPollingRequestSent(CollaboratorContext collaboratorContext) {}

    @Override
    public void onPollingResponseReceived(CollaboratorContext collaboratorContext, ArrayList<Interaction> interactions) {}

    @Override
    public void onPollingFailure(CollaboratorContext collaboratorContext, String error) {}
}
