package com.nccgroup.collaboratorplusplus.extension;

public interface ProxyServiceListener {
    void beforeStartup();
    void onStartupFail(String message);
    void onStartupSuccess(String message);
    void onShutdown();
}
