package com.nccgroup.collaboratorplusplus.extension;

public abstract class ProxyServiceAdapter implements IProxyServiceListener {
    @Override
    public void beforeStartup() {}

    @Override
    public void onStartupSuccess(String message) {}

    @Override
    public void onStartupFail(String message) {}

    @Override
    public void onShutdown() {}
}
