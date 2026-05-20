package br3kjs;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.ui.UserInterface;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.FileWriter;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class Br3kJs implements BurpExtension, HttpHandler {
    private MontoyaApi api;

    private final Set<String> seen = new TreeSet<>();

    private DefaultTableModel tableModel;
    private JLabel jsCountLabel;
    private JLabel findingCountLabel;
    private JTextArea logArea;

    private int jsCount = 0;

    private static final Pattern ENDPOINT = Pattern.compile(
            "[\"']((?:https?:)?//[^\"']+|/[a-zA-Z0-9_./?=&%\\-]{2,})[\"']"
    );

    private static final Pattern QUERY = Pattern.compile(
            "[?&]([a-zA-Z0-9_\\-]{2,})="
    );

    private static final Pattern JSON_KEY = Pattern.compile(
            "[\"']([a-zA-Z0-9_\\-]{2,})[\"']\\s*:"
    );

    private static final Pattern FORMDATA = Pattern.compile(
            "\\.append\\([\"']([a-zA-Z0-9_\\-]{2,})[\"']"
    );

    private static final Pattern HEADER = Pattern.compile(
            "[\"'](Authorization|Content-Type|Accept|X-[A-Za-z0-9\\-]+|Api-Key|X-Api-Key)[\"']",
            Pattern.CASE_INSENSITIVE
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("br3k-js");
        api.http().registerHttpHandler(this);

        UserInterface ui = api.userInterface();
        ui.registerSuiteTab("br3k-js", buildUi());

        log("[+] br3k-js loaded");
        log("[+] Passive JS analyzer is ready");
        log("[+] Browse target through Burp Proxy");
    }

    private Component buildUi() {
        JPanel root = new JPanel(new BorderLayout(12, 12));
        root.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        JPanel header = new JPanel(new BorderLayout());
        JLabel title = new JLabel("br3k-js");
        title.setFont(new Font("Segoe UI", Font.BOLD, 26));

        JLabel subtitle = new JLabel("Passive JavaScript endpoint & parameter extractor");
        subtitle.setFont(new Font("Segoe UI", Font.PLAIN, 13));

        JPanel titleBox = new JPanel(new GridLayout(2, 1));
        titleBox.add(title);
        titleBox.add(subtitle);

        header.add(titleBox, BorderLayout.WEST);

        JPanel cards = new JPanel(new GridLayout(1, 3, 10, 10));
        jsCountLabel = makeCard("JS Files", "0");
        findingCountLabel = makeCard("Findings", "0");
        JLabel modeLabel = makeCard("Mode", "Passive");

        cards.add(jsCountLabel);
        cards.add(findingCountLabel);
        cards.add(modeLabel);

        JPanel top = new JPanel(new BorderLayout(12, 12));
        top.add(header, BorderLayout.NORTH);
        top.add(cards, BorderLayout.CENTER);

        String[] columns = {"Type", "Value", "Source JS"};
        tableModel = new DefaultTableModel(columns, 0);

        JTable table = new JTable(tableModel);
        table.setAutoCreateRowSorter(true);
        table.setRowHeight(25);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        JScrollPane tableScroll = new JScrollPane(table);

        JButton clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> clearResults());

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCsv());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        buttons.add(clearBtn);
        buttons.add(exportBtn);

        logArea = new JTextArea(7, 20);
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));

        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Activity Log"));

        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.add(buttons, BorderLayout.NORTH);
        center.add(tableScroll, BorderLayout.CENTER);
        center.add(logScroll, BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);
        root.add(center, BorderLayout.CENTER);

        return root;
    }

    private JLabel makeCard(String title, String value) {
        JLabel label = new JLabel(cardHtml(title, value), SwingConstants.CENTER);
        label.setOpaque(true);
        label.setBackground(new Color(245, 247, 250));
        label.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(210, 215, 220)),
                BorderFactory.createEmptyBorder(8, 8, 8, 8)
        ));
        return label;
    }

    private String cardHtml(String title, String value) {
        return "<html><div style='text-align:center;'>"
                + "<div style='font-size:11px; color:#666;'>" + title + "</div>"
                + "<div style='font-size:24px; font-weight:bold;'>" + value + "</div>"
                + "</div></html>";
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        try {
            String url = response.initiatingRequest().url();

            String contentType = response.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                    .map(h -> h.value())
                    .findFirst()
                    .orElse("");

            boolean isJs = url.matches("(?i).*\\.js($|\\?.*)")
                    || contentType.toLowerCase().contains("javascript")
                    || contentType.toLowerCase().contains("ecmascript");

            if (!isJs) {
                return continueWith(response);
            }

            jsCount++;

            String body = response.bodyToString();

            extract("Endpoint", ENDPOINT, body, url);
            extract("Query Param", QUERY, body, url);
            extract("JSON Key", JSON_KEY, body, url);
            extract("FormData Key", FORMDATA, body, url);
            extract("Header", HEADER, body, url);

            updateStats();
            log("[+] Analyzed JS: " + url);

        } catch (Exception e) {
            log("[!] Error: " + e.getMessage());
        }

        return continueWith(response);
    }

    private void extract(String type, Pattern pattern, String body, String source) {
        Matcher matcher = pattern.matcher(body);

        while (matcher.find()) {
            String value = matcher.group(1);
            String uniqueKey = type + "|" + value + "|" + source;

            if (seen.add(uniqueKey)) {
                SwingUtilities.invokeLater(() -> {
                    tableModel.addRow(new Object[]{type, value, source});
                    updateStats();
                });
            }
        }
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            jsCountLabel.setText(cardHtml("JS Files", String.valueOf(jsCount)));
            findingCountLabel.setText(cardHtml("Findings", String.valueOf(tableModel.getRowCount())));
        });
    }

    private void clearResults() {
        seen.clear();
        jsCount = 0;
        tableModel.setRowCount(0);
        updateStats();
        log("[+] Results cleared");
    }

    private void exportCsv() {
        try {
            JFileChooser chooser = new JFileChooser();
            chooser.setSelectedFile(new java.io.File("br3k-js-results.csv"));

            int result = chooser.showSaveDialog(null);
            if (result != JFileChooser.APPROVE_OPTION) {
                return;
            }

            FileWriter writer = new FileWriter(chooser.getSelectedFile());
            writer.write("Type,Value,Source JS\n");

            for (int i = 0; i < tableModel.getRowCount(); i++) {
                writer.write(csv(tableModel.getValueAt(i, 0).toString()) + ",");
                writer.write(csv(tableModel.getValueAt(i, 1).toString()) + ",");
                writer.write(csv(tableModel.getValueAt(i, 2).toString()) + "\n");
            }

            writer.close();
            log("[+] Exported CSV: " + chooser.getSelectedFile().getAbsolutePath());

        } catch (Exception e) {
            log("[!] Export error: " + e.getMessage());
        }
    }

    private String csv(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private void log(String message) {
        api.logging().logToOutput(message);

        if (logArea != null) {
            SwingUtilities.invokeLater(() -> logArea.append(message + "\n"));
        }
    }
}