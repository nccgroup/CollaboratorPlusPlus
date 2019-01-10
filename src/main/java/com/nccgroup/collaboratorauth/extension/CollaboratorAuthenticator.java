package com.nccgroup.stepper;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.stepper.ui.StepperUI;
import com.nccgroup.stepper.ui.VariableReplacementsTabFactory;

import javax.swing.*;
import java.util.ArrayList;

public class Stepper implements IBurpExtender {

    //Vars
    public static IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private final IGsonProvider gsonProvider;
    private StepperUI ui;
    private Preferences prefs;
    private ArrayList<StepSequence> stepSequences;

    public Stepper(){
        this.gsonProvider = new DefaultGsonProvider();
        this.gsonProvider.registerTypeAdapter(new TypeToken<StepSequence>(){}.getType(), new StepSequenceSerializer(this));
        this.gsonProvider.registerTypeAdapter(new TypeToken<Step>(){}.getType(), new StepSerializer());
        this.gsonProvider.registerTypeAdapter(new TypeToken<StepVariable>(){}.getType(), new StepVariableSerializer());
    }


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        Stepper.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stepSequences = new ArrayList<>();
        this.prefs = new Preferences(this.gsonProvider, callbacks);
        configurePreferences();

        SwingUtilities.invokeLater(() -> {
            ui = new StepperUI(this);
            Stepper.callbacks.addSuiteTab(Stepper.this.ui);
            Stepper.callbacks.registerMessageEditorTabFactory(new VariableReplacementsTabFactory(this));
            Stepper.callbacks.registerContextMenuFactory(new ContextMenuFactory(Stepper.this));

            addStepSequence(new StepSequence(this));
        });

    }

    private void configurePreferences(){
        //No preferences defined.
        prefs.addSetting("sequences", String.class);
    }

    public Preferences getPreferences() {
        return prefs;
    }

    public StepperUI getUI() {
        return this.ui;
    }

    public void addStepSequence(StepSequence sequence){
        this.ui.addStepSequenceTab(sequence);
        this.stepSequences.add(sequence);
    }

    public void removeStepSet(StepSequence stepSequence){
        this.ui.removeStepSequenceTab(stepSequence);
        this.stepSequences.remove(stepSequence);
    }

    public ArrayList<StepSequence> getAllStepSets() {
        return this.stepSequences;
    }

    public IGsonProvider getGsonProvider() {
        return gsonProvider;
    }
}
