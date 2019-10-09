package com.nccgroup.collaboratorplusplus.utilities;

import burp.IBurpExtenderCallbacks;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

import java.net.URL;

public class StaticHTTPMessageController implements IMessageEditorController {

    private final IBurpExtenderCallbacks callbacks;
    private final byte[] request;
    private final byte[] response;
    private final IHttpService service;

    public StaticHTTPMessageController(IBurpExtenderCallbacks callbacks, URL url, byte[] request, byte[] response){
        this.callbacks = callbacks;
        this.request = request;
        this.response = response;

        this.service = callbacks.getHelpers().buildHttpService(url.getHost(), url.getPort(), url.getProtocol());
    }

    @Override
    public IHttpService getHttpService() {
        return this.service;
    }

    @Override
    public byte[] getRequest() {
        return this.request;
    }

    @Override
    public byte[] getResponse() {
        return this.response;
    }

    public IMessageEditor buildRequestViewer(){
        IMessageEditor editor = callbacks.createMessageEditor(this, false);
        editor.setMessage(request, true);
        return editor;
    }

    public IMessageEditor buildResponseViewer(){
        IMessageEditor editor = callbacks.createMessageEditor(this, false);
        editor.setMessage(response, false);
        return editor;
    }

}
