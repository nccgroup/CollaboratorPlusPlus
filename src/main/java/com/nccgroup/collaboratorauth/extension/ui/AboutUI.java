package com.nccgroup.collaboratorauth.extension.ui;

import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorauth.extension.CollaboratorAuthenticator;
import com.nccgroup.collaboratorauth.extension.Globals;

import javax.swing.*;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(e.getButton() == MouseEvent.BUTTON2){
                    AboutUI.this.remove(panel);
                    panel = buildMainPanel();
                    AboutUI.this.add(panel);
                    AboutUI.this.revalidate();
                    AboutUI.this.repaint();
                }
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

        BufferedImage twitterImage = loadImage("TwitterLogo.png");
        JButton twitterButton;
        if(twitterImage != null){
            twitterButton = new JButton("Follow me on Twitter", new ImageIcon(scaleImageToWidth(twitterImage, 20)));
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
        BufferedImage nccImage = loadImage("NCCGroup.png");
        if(nccImage != null){
            nccTwitterButton = new JButton("Follow NCC Group on Twitter", new ImageIcon(scaleImageToWidth(nccImage, 20)));
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
        BufferedImage githubImage = loadImage(githubLogoFilename);
        JButton viewOnGithubButton;
        if(githubImage != null){
            viewOnGithubButton = new JButton("View Project on GitHub", new ImageIcon(scaleImageToWidth(githubImage, 20)));
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


        BufferedImage nccLargeImage = loadImage("NCCLarge.png");
        ImageIcon nccLargeImageIcon = new ImageIcon(scaleImageToWidth(nccLargeImage, 300));
        JLabel nccBranding = new JLabel(nccLargeImageIcon);
        nccBranding.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentResized(ComponentEvent e) {
                int width = e.getComponent().getWidth();
                nccLargeImageIcon.setImage(scaleImageToWidth(nccLargeImage, width));
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
        aboutContent.setLayout(new BorderLayout());
        aboutContent.setEditable(false);
        aboutContent.setOpaque(false);
        aboutContent.setCaret(new NoTextSelectionCaret(aboutContent));

        JScrollPane aboutScrollPane = new JScrollPane(aboutContent);
        aboutScrollPane.setBorder(null);
        aboutScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        Style bold = aboutContent.getStyledDocument().addStyle("bold", null);
        StyleConstants.setBold(bold, true);
        Style italics = aboutContent.getStyledDocument().addStyle("italics", null);
        StyleConstants.setItalic(italics, true);

        BufferedImage explanationImageOriginal = loadImage("Explain.png");
        JLabel explanationImage = new JLabel(new ImageIcon(explanationImageOriginal));
        explanationImage.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                fitToWidth(e.getComponent().getWidth());
            }

            @Override
            public void componentResized(ComponentEvent e) {
                fitToWidth(e.getComponent().getWidth());
            }
            private void fitToWidth(int width){
                width = Math.min(600, width);
                explanationImage.setIcon(new ImageIcon(scaleImageToWidth(explanationImageOriginal, (int) Math.floor(width*0.85))));
            }
        });

        try {
            String introA = "Collaborator Abuse\n";
            String introB = "By searching Shodan.io for response headers sent by Burp Collaborator, NCC Group discovered " +
                    "the existence of 364 private collaborator servers. 160 of these were configured with SSL certificates, " +
                    "many of which with common name attributes suggesting ownership by leading security companies.\n\n" +
                    "Since Collaborator does not provide an authentication mechanism, a malicious user may " +
                    "use any of these discovered servers to exfiltrate stolen data from a compromised network.\n" +
                    "This tool aims to secure Collaborator servers by providing an authenticated proxy for polling " +
                    "for Collaborator interactions, enabling server owners to limit unauthenticated polling to the local network.\n\n";
            String explanationA = "Authentication Mechanism\n";
            String explanationB = "Collaborator Authenticator consists of two components, the server-side authentication server which " +
                    "is responsible for validating incoming polling requests before passing them to the Collaborator server, and " +
                    "the client extension which creates a local HTTP server and sets itself as the polling address.\n\n" +
                    "When Burp requests the list of interactions received by the Collaborator server, the extension " +
                    "forwards the polling requests sent by burp along with the pre-shared secret to the authentication secret. " +
                    "Provided the pre-shared secret is correct, the authentication server will query the Collaborator server and " +
                    "respond with the interactions for the given Collaborator instance.";

            String[] sections = new String[]{introA, introB, explanationA, explanationB};
            Style[] styles = new Style[]{bold, null, bold, null, bold, null, null, italics};

            StyledDocument document = aboutContent.getStyledDocument();
            for (int i = 0; i < sections.length; i++) {
                String section = sections[i];
                document.insertString(document.getLength(), String.valueOf(section), styles[i]);
            }

        } catch (Exception e) {
            StringWriter writer = new StringWriter();
            e.printStackTrace(new PrintWriter(writer));
            CollaboratorAuthenticator.callbacks.printError(writer.toString());
        }

        aboutContent.setBorder(BorderFactory.createEmptyBorder(0,0,25,0));

        try {
            JPanel panel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{headerLabel, headerLabel},
                    new JComponent[]{subtitle, subtitle},
                    new JComponent[]{separator, separator},
                    new JComponent[]{separatorPadding, separatorPadding},
                    new JComponent[]{creditsPanel, twitterButton},
                    new JComponent[]{creditsPanel, nccTwitterButton},
                    new JComponent[]{creditsPanel, viewOnGithubButton},
                    new JComponent[]{aboutContent, aboutContent},
                    new JComponent[]{explanationImage, explanationImage},
                    new JComponent[]{new JPanel(), null},
            }, new int[][]{
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{100,100},
            }, PanelBuilder.Alignment.TOPMIDDLE, 0.25, 1D);
            return panel;
        } catch (Exception e) {
            return new JLabel("Failed to build credits panel :(");
        }
    }

    private BufferedImage loadImage(String filename){
        ClassLoader cldr = this.getClass().getClassLoader();
        URL imageURLMain = cldr.getResource(filename);

        if(imageURLMain != null) {
            Image original = new ImageIcon(imageURLMain).getImage();
            ImageIcon originalIcon = new ImageIcon(original);
            BufferedImage bufferedImage = new BufferedImage(originalIcon.getIconWidth(), originalIcon.getIconHeight(), BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.drawImage(originalIcon.getImage(), null, null);
            return bufferedImage;
        }
        return null;
    }

    private Image scaleImageToWidth(BufferedImage image, int width){
        int height = (int) (Math.floor((image.getHeight() * width) / (double) image.getWidth()));
        return image.getScaledInstance(width, height, Image.SCALE_SMOOTH);
    }
}
