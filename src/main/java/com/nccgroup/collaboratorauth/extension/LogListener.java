package com.nccgroup.collaboratorauth.extension;

public interface LogListener {
    void onInfo(String message);
    void onError(String message);
    void onDebug(String message);
}
