package com.nccgroup.collaboratorauth.server;

import com.jdotsoft.jarloader.JarClassLoader;

public class Launcher {
    public static void main(String[] args) {
        JarClassLoader jcl = new JarClassLoader();
        try {
            jcl.invokeMain("com.nccgroup.collaboratorauth.server.CollaboratorServer", args);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}
