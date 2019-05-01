package com.nccgroup.collaboratorauth.extension;

import com.nccgroup.collaboratorauth.extension.ui.ConfigUI;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

public class LogController {

    private final ArrayList<LogListener> logListeners;

    enum LogLevel {INFO, ERROR, DEBUG}

    public LogController(){
        this.logListeners = new ArrayList();
    }

    public void addLogListener(LogListener logListener) {
        this.logListeners.add(logListener);
    }

    public void removeLogListener(LogListener logListener){
        this.logListeners.remove(logListener);
    }

    public void logError(String message){
        for (LogListener logListener : this.logListeners) {
            logListener.onError(message);
        }
    }

    public void logInfo(String message){
        for (LogListener logListener : this.logListeners) {
            logListener.onInfo(message);
        }
    }

    public void logDebug(String message){
        for (LogListener logListener : this.logListeners) {
            logListener.onDebug(message);
        }
    }

    public void logError(Exception ex){
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        for (LogListener logListener : logListeners) {
            logListener.onError(sw.toString());
        }
    }
}
