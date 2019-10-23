package com.nccgroup.collaboratorplusplus.extension;

import javax.swing.*;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.util.function.Consumer;

public class BurpTabWatcher implements ContainerListener {

    JComponent watchedComponent;

    public BurpTabWatcher(JComponent watched){
        this.watchedComponent = watched;
    }

    public JComponent getWatchedComponent() {
        return watchedComponent;
    }

    @Override
    public void componentAdded(ContainerEvent containerEvent) {

    }

    @Override
    public void componentRemoved(ContainerEvent containerEvent) {

    }
}
