package com.nccgroup.collaboratorplusplus.extension;

import com.nccgroup.collaboratorplusplus.extension.context.Interaction;

import java.util.ArrayList;

public interface CollaboratorEventListener {
    void onPollingRequestSent(String biid, boolean isFirstPoll);
    void onPollingResponseReceived(String biid, ArrayList<Interaction> interactions);
    void onPollingFailure(String error);
}
