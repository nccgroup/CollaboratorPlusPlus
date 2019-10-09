package com.nccgroup.collaboratorplusplus.utilities;

import javax.swing.*;

public class SelectableLabel extends JTextField {

    public SelectableLabel(String text){
        super(text);
        this.setEditable(false);
        this.setBorder(null);
    }
}
