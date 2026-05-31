package br3kjs;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.RowFilter;
import java.awt.*;
import java.io.FileWriter;
import java.util.Set;
import java.util.Collections;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static burp.api.montoya.http.handler.RequestToBeSentAction.continueWith;
import static burp.api.montoya.http.handler.ResponseReceivedAction.continueWith;

public class Br3kJs implements BurpExtension, HttpHandler {
    private MontoyaApi api;

    // Use a thread-safe ConcurrentHashMap-backed Set to prevent race conditions
    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    private DefaultTableModel tableModel;
    private JTable table;
    private TableRowSorter<DefaultTableModel> sorter;
    
    private JTextField filterTextField;
    private JComboBox<String> typeFilterCombo;

    private JLabel jsCountValue;
    private JLabel findingCountValue;
    private JTextArea logArea;

    private JCheckBox onlyInScopeCheckbox;
    private JCheckBox analyzeHtmlCheckbox;

    // Use AtomicInteger for thread-safe counters
    private final AtomicInteger jsCount = new AtomicInteger(0);

    // Regex patterns improved to support backticks (`) and template literals
    private static final Pattern ENDPOINT = Pattern.compile(
            "[\"`']((?:https?:)?//[^\"`']+|/[a-zA-Z0-9_./?=&%\\-]{2,})[\"`']"
    );

    // Captures URL parameters and URLSearchParams methods (append, set, etc.)
    private static final Pattern QUERY = Pattern.compile(
            "[?&]([a-zA-Z0-9_\\-]{2,})=|(?:\\bparams|\\bsearchParams)\\.(?:append|set|get|has)\\([\"'`]([a-zA-Z0-9_\\-]{2,})[\"'`]",
            Pattern.CASE_INSENSITIVE
    );

    // Captures quoted keys as well as modern JS unquoted object keys (username: "admin")
    private static final Pattern JSON_KEY = Pattern.compile(
            "[\"`']([a-zA-Z0-9_\\-]{2,})[\"`']\\s*:|\\b([a-zA-Z0-9_\\-]{2,})\\s*:\\s*(?:[\"`'{]|-?\\d|true|false|null|\\[)"
    );

    private static final Pattern FORMDATA = Pattern.compile(
            "\\.append\\([\"'`]([a-zA-Z0-9_\\-]{2,})[\"'`]"
    );

    private static final Pattern HEADER = Pattern.compile(
            "[\"`'](Authorization|Content-Type|Accept|X-[A-Za-z0-9\\-]+|Api-Key|X-Api-Key|Token|Bearer|X-CSRF-Token|X-Auth-Token|X-Requested-With)[\"`']",
            Pattern.CASE_INSENSITIVE
    );

    // Regex to extract contents of <script> tags from HTML responses
    private static final Pattern SCRIPT_TAG = Pattern.compile(
            "<script[^>]*>(.*?)</script>",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;

        api.extension().setName("br3k-js");
        api.http().registerHttpHandler(this);

        UserInterface ui = api.userInterface();
        ui.registerSuiteTab("br3k-js", buildUi());

        // Register Context Menu Provider for manual analysis from HTTP History / other tools
        ui.registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<HttpRequestResponse> selectedItems = event.selectedRequestResponses();
                if (selectedItems == null || selectedItems.isEmpty()) {
                    return Collections.emptyList();
                }

                JMenuItem analyzeItem = new JMenuItem("Analyze JS/HTML in br3k-js");
                analyzeItem.addActionListener(e -> {
                    new Thread(() -> {
                        log("[+] Manually analyzing " + selectedItems.size() + " selected items...");
                        int count = 0;
                        for (HttpRequestResponse reqResp : selectedItems) {
                            if (reqResp.response() != null) {
                                analyzeResponse(reqResp.request(), reqResp.response());
                                count++;
                            }
                        }
                        log("[+] Manual analysis completed. Checked " + count + " items.");
                    }).start();
                });

                return List.of(analyzeItem);
            }
        });

        log("[+] br3k-js loaded");
        log("[+] Passive JS & HTML script analyzer is ready");
        log("[+] Browse target or right-click HTTP History items to analyze manually");
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

        JPanel jsCard = makeCard("JS & HTML Files", "0");
        JPanel findingCard = makeCard("Findings", "0");
        JPanel modeCard = makeCard("Mode", "Passive");

        jsCountValue = (JLabel) jsCard.getComponent(1);
        findingCountValue = (JLabel) findingCard.getComponent(1);

        cards.add(jsCard);
        cards.add(findingCard);
        cards.add(modeCard);

        JPanel top = new JPanel(new BorderLayout(12, 12));
        top.add(header, BorderLayout.NORTH);
        top.add(cards, BorderLayout.CENTER);

        String[] columns = {"Type", "Value", "Source JS"};
        tableModel = new DefaultTableModel(columns, 0);

        table = new JTable(tableModel);
        sorter = new TableRowSorter<>(tableModel);
        table.setRowSorter(sorter);
        table.setAutoCreateRowSorter(false); // Let custom RowSorter handle sorting
        table.setRowHeight(25);
        table.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 12));
        table.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        JScrollPane tableScroll = new JScrollPane(table);

        JButton clearBtn = new JButton("Clear Results");
        clearBtn.addActionListener(e -> clearResults());

        JButton exportBtn = new JButton("Export CSV");
        exportBtn.addActionListener(e -> exportCsv());

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        buttons.add(clearBtn);
        buttons.add(exportBtn);

        // Options Checkboxes Panel
        onlyInScopeCheckbox = new JCheckBox("Only In-Scope");
        onlyInScopeCheckbox.setSelected(false);
        onlyInScopeCheckbox.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        analyzeHtmlCheckbox = new JCheckBox("Analyze HTML Script Tags");
        analyzeHtmlCheckbox.setSelected(true);
        analyzeHtmlCheckbox.setFont(new Font("Segoe UI", Font.PLAIN, 12));

        JPanel optionsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 15, 0));
        optionsPanel.add(onlyInScopeCheckbox);
        optionsPanel.add(analyzeHtmlCheckbox);

        // Filter Bar Panel
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        
        JLabel filterLabel = new JLabel("Filter Search:");
        filterLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        
        filterTextField = new JTextField(20);
        filterTextField.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        filterTextField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilter(); }
        });
        
        JLabel typeLabel = new JLabel("Filter Type:");
        typeLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
        
        String[] types = {"All", "Endpoint", "Query Param", "JSON Key", "FormData Key", "Header"};
        typeFilterCombo = new JComboBox<>(types);
        typeFilterCombo.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        typeFilterCombo.addActionListener(e -> applyFilter());
        
        filterPanel.add(filterLabel);
        filterPanel.add(filterTextField);
        filterPanel.add(typeLabel);
        filterPanel.add(typeFilterCombo);

        JPanel controls = new JPanel(new BorderLayout(8, 8));
        
        JPanel topRow = new JPanel(new BorderLayout());
        topRow.add(buttons, BorderLayout.WEST);
        topRow.add(optionsPanel, BorderLayout.EAST);
        
        controls.add(topRow, BorderLayout.NORTH);
        controls.add(filterPanel, BorderLayout.SOUTH);

        logArea = new JTextArea(7, 20);
        logArea.setEditable(false);
        logArea.setFont(new Font("Consolas", Font.PLAIN, 12));

        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setBorder(BorderFactory.createTitledBorder("Activity Log"));

        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.add(controls, BorderLayout.NORTH);
        center.add(tableScroll, BorderLayout.CENTER);
        center.add(logScroll, BorderLayout.SOUTH);

        root.add(top, BorderLayout.NORTH);
        root.add(center, BorderLayout.CENTER);

        return root;
    }

    private JPanel makeCard(String title, String value) {
        JPanel panel = new JPanel(new GridLayout(2, 1));
        panel.setBackground(new Color(245, 247, 250));
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(210, 215, 220)),
                BorderFactory.createEmptyBorder(12, 12, 12, 12)
        ));

        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setFont(new Font("Segoe UI", Font.PLAIN, 12));
        titleLabel.setForeground(new Color(90, 90, 90));

        JLabel valueLabel = new JLabel(value, SwingConstants.CENTER);
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 24));
        valueLabel.setForeground(new Color(30, 30, 30));

        panel.add(titleLabel);
        panel.add(valueLabel);

        return panel;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return continueWith(request);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        analyzeResponse(response.initiatingRequest(), response);
        return continueWith(response);
    }

    private void analyzeResponse(HttpRequest request, HttpResponse response) {
        if (request == null || response == null) {
            return;
        }

        try {
            String url = request.url();

            // 1. Scope Filter Check
            if (onlyInScopeCheckbox != null && onlyInScopeCheckbox.isSelected()) {
                if (!request.isInScope()) {
                    return;
                }
            }

            // Extract Content-Type
            String contentType = response.headers().stream()
                    .filter(h -> h.name().equalsIgnoreCase("Content-Type"))
                    .map(h -> h.value())
                    .findFirst()
                    .orElse("");

            // 2. Identify if it is JS or HTML
            boolean isJs = url.matches("(?i).*\\.js($|\\?.*)")
                    || contentType.toLowerCase().contains("javascript")
                    || contentType.toLowerCase().contains("ecmascript");

            boolean isHtml = contentType.toLowerCase().contains("html")
                    || url.matches("(?i).*\\.html?($|\\?.*)");

            if (!isJs && !isHtml) {
                return;
            }

            // Respect HTML option
            if (isHtml && (analyzeHtmlCheckbox == null || !analyzeHtmlCheckbox.isSelected())) {
                return;
            }

            String body = response.bodyToString();
            if (body == null || body.isEmpty()) {
                return;
            }

            jsCount.incrementAndGet();

            if (isJs) {
                runExtractors(body, url);
                log("[+] Analyzed JS: " + url);
            } else if (isHtml) {
                Matcher scriptMatcher = SCRIPT_TAG.matcher(body);
                int scriptCount = 0;
                while (scriptMatcher.find()) {
                    String scriptContent = scriptMatcher.group(1);
                    if (scriptContent != null && !scriptContent.trim().isEmpty()) {
                        runExtractors(scriptContent, url);
                        scriptCount++;
                    }
                }
                if (scriptCount > 0) {
                    log("[+] Analyzed HTML (extracted " + scriptCount + " script tags): " + url);
                }
            }

            updateStats();

        } catch (Exception e) {
            log("[!] Error analyzing response: " + e.getMessage());
        }
    }

    private void runExtractors(String content, String url) {
        extract("Endpoint", ENDPOINT, content, url);
        extract("Query Param", QUERY, content, url);
        extract("JSON Key", JSON_KEY, content, url);
        extract("FormData Key", FORMDATA, content, url);
        extract("Header", HEADER, content, url);
    }

    private void extract(String type, Pattern pattern, String body, String source) {
        Matcher matcher = pattern.matcher(body);

        while (matcher.find()) {
            String value = null;
            // Iterate over all capture groups to find the first non-null match
            for (int i = 1; i <= matcher.groupCount(); i++) {
                if (matcher.group(i) != null) {
                    value = matcher.group(i);
                    break;
                }
            }

            if (value != null) {
                value = value.trim();
                // Filter out empty or extremely short results to keep findings high quality
                if (value.length() >= 2) {
                    String uniqueKey = type + "|" + value + "|" + source;

                    if (seen.add(uniqueKey)) {
                        final String finalValue = value;
                        SwingUtilities.invokeLater(() -> {
                            tableModel.addRow(new Object[]{type, finalValue, source});
                            updateStats();
                        });
                    }
                }
            }
        }
    }

    private void applyFilter() {
        if (sorter == null) {
            return;
        }

        String text = filterTextField.getText().trim();
        String selectedType = (String) typeFilterCombo.getSelectedItem();

        List<RowFilter<DefaultTableModel, Object>> filters = new ArrayList<>();

        // Text search filter (case-insensitive search across all columns)
        if (!text.isEmpty()) {
            filters.add(RowFilter.regexFilter("(?i)" + Pattern.quote(text)));
        }

        // Type filter
        if (selectedType != null && !selectedType.equals("All")) {
            filters.add(RowFilter.regexFilter("^" + Pattern.quote(selectedType) + "$", 0));
        }

        if (filters.isEmpty()) {
            sorter.setRowFilter(null);
        } else {
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }

        updateStats();
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            jsCountValue.setText(String.valueOf(jsCount.get()));
            
            if (table != null) {
                int totalRows = tableModel.getRowCount();
                int visibleRows = table.getRowCount();
                if (visibleRows == totalRows) {
                    findingCountValue.setText(String.valueOf(totalRows));
                } else {
                    findingCountValue.setText(visibleRows + " / " + totalRows);
                }
            } else {
                findingCountValue.setText(String.valueOf(tableModel.getRowCount()));
            }
        });
    }

    private void clearResults() {
        seen.clear();
        jsCount.set(0);
        tableModel.setRowCount(0);
        
        if (filterTextField != null) {
            filterTextField.setText("");
        }
        if (typeFilterCombo != null) {
            typeFilterCombo.setSelectedIndex(0);
        }
        
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