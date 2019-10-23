package com.nccgroup.collaboratorplusplus.extension.exception;

public class InvalidResponseException extends CollaboratorPollingException {

    public InvalidResponseException(String message){
        super(message);
    }
}
