package com.nccgroup.collaboratorplusplus.extension.ui;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.collaboratorplusplus.extension.CollaboratorPlusPlus;
import com.nccgroup.collaboratorplusplus.extension.Globals;

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

    private final CollaboratorPlusPlus collaboratorPlusPlus;
    private final Preferences preferences;
    private JComponent panel;

    public AboutUI(CollaboratorPlusPlus collaboratorPlusPlus){
        this.setLayout(new BorderLayout());
        this.collaboratorPlusPlus = collaboratorPlusPlus;
        this.preferences = collaboratorPlusPlus.getPreferences();

        this.panel = buildMainPanel();
        this.add(panel, BorderLayout.NORTH);
        this.setMinimumSize(panel.getSize());
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(e.getButton() == MouseEvent.BUTTON2){
                    AboutUI.this.removeAll();
                    panel = buildMainPanel();
                    AboutUI.this.add(panel, BorderLayout.NORTH);
                    AboutUI.this.setMinimumSize(panel.getSize());
                    AboutUI.this.revalidate();
                    AboutUI.this.repaint();
                }
            }
        });
    }

    private JComponent buildMainPanel(){
        PanelBuilder panelBuilder = new PanelBuilder(preferences);

        JLabel headerLabel = new JLabel("Collaborator++");
        Font font = this.getFont().deriveFont(32f).deriveFont(this.getFont().getStyle() | Font.BOLD);
        headerLabel.setFont(font);
        headerLabel.setHorizontalAlignment(SwingConstants.CENTER);


        JLabel subtitle = new JLabel("Enhanced client for secure collaborator interaction");
        Font subtitleFont = subtitle.getFont().deriveFont(16f).deriveFont(subtitle.getFont().getStyle() | Font.ITALIC);
        subtitle.setFont(subtitleFont);
        subtitle.setHorizontalAlignment(SwingConstants.CENTER);

        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        JPanel separatorPadding = new JPanel();
        separatorPadding.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));

        BufferedImage twitterImage = loadImage("TwitterLogo.png");
        JButton twitterButton;
        if(twitterImage != null){
            twitterButton = new JButton("Follow me (@CoreyD97) on Twitter", new ImageIcon(scaleImageToWidth(twitterImage, 20)));
            twitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            twitterButton.setIconTextGap(7);
        }else{
            twitterButton = new JButton("Follow me (@CoreyD97) on Twitter");
        }

        twitterButton.setMaximumSize(new Dimension(0, 10));

        twitterButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI(Globals.TWITTER_URL));
            } catch (IOException | URISyntaxException e) {}
        });

        JButton irsdlTwitterButton;
        if(twitterImage != null){
            irsdlTwitterButton = new JButton("Follow Soroush (@irsdl) on Twitter", new ImageIcon(scaleImageToWidth(twitterImage, 20)));
            irsdlTwitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
            irsdlTwitterButton.setIconTextGap(7);
        }else{
            irsdlTwitterButton = new JButton("Follow Soroush (@irsdl) on Twitter");
        }

        irsdlTwitterButton.setMaximumSize(new Dimension(0, 10));

        irsdlTwitterButton.addActionListener(actionEvent -> {
            try {
                Desktop.getDesktop().browse(new URI(Globals.IRSDL_TWITTER_URL));
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
        JLabel ideaBy = new JLabel("Idea by: Soroush Dalili ( @irsdl )");
        ideaBy.setHorizontalAlignment(SwingConstants.CENTER);
        ideaBy.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));
        JComponent creditsPanel;
        try {
            creditsPanel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{createdBy},
                    new JComponent[]{ideaBy},
                    new JComponent[]{nccBranding},
                    new JComponent[]{nccBranding}
            }, Alignment.FILL, 1, 1);
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
            String intro = "When testing for out-of-band vulnerabilities, Collaborator has been an invaluable tool since its initial release in 2015. " +
                    "However, some issues remain which hinder its effectiveness. While Collaborator contexts created as part of scans " +
                    "are saved within the Burp project, there is currently no method of polling old contexts such as those created with " +
                    "extensions such as Collaborator Everywhere or the Collaborator Client. " +
                    "Additionally, while private Collaborator instances may be deployed, there is currently no " +
                    "authentication mechanism to restrict usage besides limiting polling to an internal network. \n\n" +
                    "This extension aims to aleviate those issues.\n\n";

            String instructions = "Instructions\n";
            String instructionsContent = "To use Collaborator++, simply configure the extension to target your Collaborator server and start the extension.\n" +
                    "A local server will be started and Burp will be configured to direct all polling requests to it.\n" +
                    "The extension will then use the options configured to make a request to the polling server on behalf of Burp. " +
                    "This allows control of various options such as ignoring SSL issues, and allows the extension to capture " +
                    "the Collaborator context identifiers and associated interactions for future display and manual polling.\n\n";
            String auth = "Authentication\n";
            String authInstructions = "In addition to being able to control various configuration aspects of the polling request, " +
                    "the ability to modify the request also allows the extension to add an authentication mechanism to private collaborator instances.\n\n" +
                    "This is achieved by using a shared secret known by both the client and server to generate a symmetric encryption key " +
                    "which is used to encrypt communication between the client and server using AES256. " +
                    "In addition to authentication, this also enables the usage of HTTP without loss of confidentiality should SSL not be available " +
                    "for any reason.\n\n" +
                    "To use authentication, ensure that the server you wish to use is running the Collaborator++ auth server component " +
                    "and simply configure this extension to target it, making sure to set the port as configured by the server.\n" +
                    "Details on how to setup the server component can be found on the projects GitHub page.";


            String[] sections = new String[]{intro, instructions, instructionsContent, auth, authInstructions};
            Style[] styles = new Style[]{null, bold, null, bold, null, null, italics};

            StyledDocument document = aboutContent.getStyledDocument();
            for (int i = 0; i < sections.length; i++) {
                String section = sections[i];
                document.insertString(document.getLength(), String.valueOf(section), styles[i]);
            }

        } catch (Exception e) {
            StringWriter writer = new StringWriter();
            e.printStackTrace(new PrintWriter(writer));
            CollaboratorPlusPlus.callbacks.printError(writer.toString());
        }

        aboutContent.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
        JScrollPane aboutContentScrollPane = new JScrollPane(aboutContent);
        aboutContentScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

        try {
            JPanel panel = panelBuilder.build(new JComponent[][]{
                    new JComponent[]{headerLabel, headerLabel},
                    new JComponent[]{subtitle, subtitle},
                    new JComponent[]{separator, separator},
                    new JComponent[]{separatorPadding, separatorPadding},
                    new JComponent[]{creditsPanel, twitterButton},
                    new JComponent[]{creditsPanel, irsdlTwitterButton},
                    new JComponent[]{creditsPanel, nccTwitterButton},
                    new JComponent[]{creditsPanel, viewOnGithubButton},
                    new JComponent[]{aboutContentScrollPane, aboutContentScrollPane},
                    new JComponent[]{explanationImage, explanationImage},
            }, new int[][]{
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{1,1},
                    new int[]{200,200},
                    new int[]{0,0},
            }, Alignment.TOPMIDDLE, 0.5, 1D);
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
