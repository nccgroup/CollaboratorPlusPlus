package com.nccgroup.collaboratorauth.extension;

import java.util.ArrayList;

public class InteractionLogger {

    private final CollaboratorAuthenticator extension;
    private final ArrayList<Interaction> interactions;

    public InteractionLogger(CollaboratorAuthenticator extension){
        this.extension = extension;
        this.interactions = new ArrayList<Interaction>();
    }



}
