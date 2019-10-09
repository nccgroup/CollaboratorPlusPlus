package com.nccgroup.collaboratorplusplus.utilities;

import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.nccgroup.collaboratorplusplus.extension.LogListener;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;

public class LogManager {

    public enum LogLevel {INFO, ERROR, DEBUG;}
    private final ArrayList<LogListener> logListeners;
    private LogLevel logLevel;

    public LogManager(){
        this.logListeners = new ArrayList();
        this.logLevel = LogLevel.DEBUG;
    }

    public LogLevel getLogLevel() {
        return this.logLevel;
    }

    public void setLogLevel(LogLevel logLevel){
        this.logLevel = logLevel;
    }

    public void addLogListener(LogListener logListener) {
        this.logListeners.add(logListener);
    }

    public void removeLogListener(LogListener logListener){
        this.logListeners.remove(logListener);
    }

    public void logInfo(String message){
        if(logLevel.ordinal() >= LogLevel.INFO.ordinal()) {
            for (LogListener logListener : this.logListeners) {
                logListener.onInfo(message);
            }
        }
    }

    public void logError(String message){
        if(logLevel.ordinal() >= LogLevel.ERROR.ordinal()) {
            for (LogListener logListener : this.logListeners) {
                logListener.onError(message);
            }
        }
    }

    public void logError(Exception ex){
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        logError(sw.toString());
    }

    public void logDebug(String message){
        if(logLevel.ordinal() >= LogLevel.DEBUG.ordinal()) {
            for (LogListener logListener : this.logListeners) {
                logListener.onDebug(message);
            }
        }
    }

    public void logDebug(Exception ex){
        StringWriter sw = new StringWriter();
        ex.printStackTrace(new PrintWriter(sw));
        logDebug(sw.toString());
    }
}
