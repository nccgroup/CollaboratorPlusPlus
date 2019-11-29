package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorContext;
import com.nccgroup.collaboratorplusplus.extension.context.CollaboratorServer;
import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import java.util.ArrayList;

public interface CollaboratorEventListener {
    void onCollaboratorServerRegistered(CollaboratorServer collaboratorServer, int index);
    void onCollaboratorServerRemoved(CollaboratorServer collaboratorServer, int index);
    void onCollaboratorContextRegistered(CollaboratorContext collaboratorContext, int index);
    void onCollaboratorContextRemoved(CollaboratorContext collaboratorContext, int index);
    void onPollingRequestSent(CollaboratorContext collaboratorContext);
    void onPollingResponseReceived(CollaboratorContext collaboratorContext, ArrayList<Interaction> interactions);
    void onPollingFailure(CollaboratorContext collaboratorContext, String error);
}
