package com.nccgroup.collaboratorauth.extension.ui;

import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;
import com.nccgroup.collaboratorauth.extension.Globals;

import javax.swing.*;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class AboutUI extends JPanel {

    private final CollaboratorAuthenticator collaboratorAuthenticator;
    private final Preferences preferences;
    private JComponent panel;

    public AboutUI(CollaboratorAuthenticator collaboratorAuthenticator){
        this.setLayout(new BorderLayout());
        this.collaboratorAuthenticator = collaboratorAuthenticator;
        this.preferences = collaboratorAuthenticator.getPreferences();

        this.panel = buildMainPanel();
        this.add(panel, BorderLayout.CENTER);
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                AboutUI.this.removeAll();
                AboutUI.this.panel = buildMainPanel();
                AboutUI.this.add(AboutUI.this.panel, BorderLayout.CENTER);
//                AboutUI.this.revalidate();
//                AboutUI.this.repaint();
            }
        });
    }

    private JComponent buildMainPanel(){
        PanelBuilder panelBuilder = new PanelBuilder(preferences);

        JLabel headerLabel = new JLabel("Collaborator Authenticator");
        Font font = this.getFont().deriveFont(32f).deriveFont(this.getFont().getStyle() | Font.BOLD);
        headerLabel.setFont(font);
        headerLabel.setHorizontalAlignment(SwingConstants.CENTER);


        JLabel subtitle = new JLabel("Client for secure collaborator interaction");
        Font subtitleFont = subtitle.getFont().deriveFont(16f).deriveFont(subtitle.getFont().getStyle() | Font.ITALIC);
        subtitle.setFont(subtitleFont);
        subtitle.setHorizontalAlignment(SwingConstants.CENTER);

        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        JPanel separatorPadding = new JPanel();
        separatorPadding.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));

        ImageIcon twitterImage = loadImage("TwitterLogo.png", 20, 20);
        JButton twitterButton;
        if(twitterImage != null){
            twitterButton = new JButton("Follow me on Twitter", twitterImage);
            twitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            twitterButton.setIconTextGap(7);
        }else{
            twitterButton = new JButton("Follow me on Twitter");
        }

        twitterButton.setMaximumSize(new Dimension(0, 10));

        twitterButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI(Globals.TWITTER_URL));
            } catch (IOException | URISyntaxException e) {}
        });

        JButton nccTwitterButton;
        ImageIcon nccImage = loadImage("NCCGroup.png", 20, 20);
        if(nccImage != null){
            nccTwitterButton = new JButton("Follow NCC Group on Twitter", nccImage);
            nccTwitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            nccTwitterButton.setIconTextGap(7);
        }else{
            nccTwitterButton = new JButton("Follow NCC Group on Twitter");
        }

        nccTwitterButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI(Globals.NCC_TWITTER_URL));
            } catch (IOException | URISyntaxException e) {}
        });

        String githubLogoFilename = "GitHubLogo" +
                (UIManager.getLookAndFeel().getName().equalsIgnoreCase("darcula") ? "White" : "Black")
                + ".png";
        ImageIcon githubImage = loadImage(githubLogoFilename, 20, 20);
        JButton viewOnGithubButton;
        if(githubImage != null){
            viewOnGithubButton = new JButton("View Project on GitHub", githubImage);
            viewOnGithubButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            viewOnGithubButton.setIconTextGap(7);
        }else{
            viewOnGithubButton = new JButton("View Project on GitHub");
        }
        viewOnGithubButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI(Globals.GITHUB_URL));
            } catch (IOException | URISyntaxException e) {}
        });


        double ratio = 75D/300;
        ImageIcon nccLargeImage = loadImage("NCCLarge.png", 300, 75);
        JLabel nccBranding = new JLabel(nccLargeImage);
        nccBranding.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                JLabel label = (JLabel) e.getComponent();
                Dimension size = label.getSize();
                Image resized = nccLargeImage.getImage().getScaledInstance(size.width, (int) Math.floor(size.width*ratio), Image.SCALE_DEFAULT);
                label.setIcon(new ImageIcon(resized));
            }
        });

        JLabel createdBy = new JLabel("Created by: Corey Arthur ( @CoreyD97 )");
        createdBy.setHorizontalAlignment(SwingConstants.CENTER);
        createdBy.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));
        JComponent creditsPanel;
        try {
            creditsPanel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{createdBy},
                    new JComponent[]{nccBranding}
            }, PanelBuilder.Alignment.FILL, 1, 1);
        }catch (Exception e){
            creditsPanel = new JLabel("Could not build Panel");
        }

        WrappedTextPane aboutContent = new WrappedTextPane();
        aboutContent.setEditable(false);
        aboutContent.setOpaque(false);
        aboutContent.setCaret(new NoTextSelectionCaret(aboutContent));

        JScrollPane aboutScrollPane = new JScrollPane(aboutContent);
        aboutScrollPane.setBorder(null);
        Style bold = aboutContent.getStyledDocument().addStyle("bold", null);
        StyleConstants.setBold(bold, true);
        Style italics = aboutContent.getStyledDocument().addStyle("italics", null);
        StyleConstants.setItalic(italics, true);

        try {
            String introB = "Collaborator Abuse\n";
            String introC = "By searching Shodan for response headers sent by Burp Collaborator, NCC Group discovered " +
                    "the existence of 364 private collaborator servers. 160 of these were configured with SSL certificates, " +
                    "many of which with common name attributes suggesting ownership by leading security companies.\n\n";
            String introD = "Since Collaborator does not provide an authentication mechanism, a malicious user may " +
                    "use any of these discovered servers to exfiltrate stolen data from a compromised network.\n" +
                    "This tool aims to secure Collaborator servers by providing an authenticated proxy for polling " +
                    "for Collaborator interactions, enabling server owners to limit unauthenticated polling to the local network.";


            //Doing this an odd way since insertString seems to cause errors on windows!
            int offset = 0;
            String[] sections = new String[]{introB, introC, introD};
            Style[] styles = new Style[]{bold, null, null, null, bold, null, bold, null, null, italics};
            String content = String.join("", sections);
            aboutContent.setText(content);
            for (int i = 0; i < sections.length; i++) {
                String section = sections[i];
                if(styles[i] != null)
                    aboutContent.getStyledDocument().setCharacterAttributes(offset, section.length(), styles[i], false);
                offset+=section.length();
            }

        } catch (Exception e) {
            StringWriter writer = new StringWriter();
            e.printStackTrace(new PrintWriter(writer));
            CollaboratorAuthenticator.callbacks.printError(writer.toString());
        }

        try {
            JPanel panel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{headerLabel, headerLabel},
                    new JComponent[]{subtitle, subtitle},
                    new JComponent[]{separator, separator},
                    new JComponent[]{separatorPadding, separatorPadding},
                    new JComponent[]{creditsPanel, twitterButton},
                    new JComponent[]{creditsPanel, nccTwitterButton},
                    new JComponent[]{creditsPanel, viewOnGithubButton},
                    new JComponent[]{aboutScrollPane, aboutScrollPane},
            }, new int[][]{
                    new int[]{0,0},
                    new int[]{0,0},
                    new int[]{0,0},
                    new int[]{0,0},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1000,1000},
            }, PanelBuilder.Alignment.TOPMIDDLE, 0.25, 1);
            return panel;
        } catch (Exception e) {
            return new JLabel("Failed to build credits panel :(");
        }
    }

    private ImageIcon loadImage(String filename, int width, int height){
        ClassLoader cldr = this.getClass().getClassLoader();
        URL imageURLMain = cldr.getResource(filename);

        if(imageURLMain != null) {
            Image scaled = new ImageIcon(imageURLMain).getImage().getScaledInstance(width, height, Image.SCALE_SMOOTH);
            ImageIcon scaledIcon = new ImageIcon(scaled);
            BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.drawImage(scaledIcon.getImage(), null, null);
            return new ImageIcon(bufferedImage);
        }
        return null;
    }
}
