package com.nccgroup.collaboratorplusplus.extension;

public interface IProxyServiceListener {
    void beforeStartup();
    void onStartupSuccess(String message);
    void onStartupFail(String message);
    void onShutdown();
}
