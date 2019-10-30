package com.nccgroup.collaboratorplusplus.extension;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.function.Function;

public class BurpTabController implements ContainerListener {

    JTabbedPane watchedComponent;
    Component targetComponent;
    Function onAdd, onRemove;

    int tabIndex;
    Color currentColor;


    public BurpTabController(JTabbedPane watched, Component targetComponent, Function onAdd, Function onRemove){
        this.watchedComponent = watched;
        this.targetComponent = targetComponent;
        this.onAdd = onAdd;
        this.onRemove = onRemove;
        this.watchedComponent.addContainerListener(this);
        tabIndex = this.watchedComponent.indexOfComponent(targetComponent);

        watchedComponent.addPropertyChangeListener(new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if(evt.getPropertyName().equalsIgnoreCase("indexForTabComponent")){
                    if(evt.getNewValue().equals(tabIndex)){
                        setTabColor(currentColor);
                    }
                }
            }
        });
    }

    @Override
    public void componentAdded(ContainerEvent containerEvent) {
        if(containerEvent.getChild() == targetComponent){
            tabIndex = watchedComponent.indexOfComponent(targetComponent);
            setTabColor(this.currentColor);
        }
    }

    @Override
    public void componentRemoved(ContainerEvent containerEvent) {
        if(containerEvent.getChild() == targetComponent){
            tabIndex = -1;
        }
    }

    public void setTabColor(Color color){
        this.currentColor = color;
        JTextField titleComponent = getTabTextComponent();
        if(titleComponent != null){
            SwingUtilities.invokeLater(() -> {
                titleComponent.setDisabledTextColor(color);
                titleComponent.repaint();
            });
        }
    }

    public void flashTabColor(Color color){

    }

    private JTextField getTabTextComponent(){
        if(tabIndex != -1){
            JComponent tabComponent = (JComponent) this.watchedComponent.getTabComponentAt(tabIndex);
            if(tabComponent != null) {
                return (JTextField) tabComponent.getComponent(0);
            }
        }
        return null;
    }
}
