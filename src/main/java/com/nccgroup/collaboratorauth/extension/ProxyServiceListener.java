package com.nccgroup.collaboratorauth.extension;

public interface ProxyServiceListener {
    void onFail(String message);
    void onSuccess(String message);
}
