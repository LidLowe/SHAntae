package kz.team.aesmy.shantae.Controller;

import javafx.fxml.FXML;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.stage.FileChooser;
import kz.team.aesmy.shantae.SHA256.SHA256;
import kz.team.aesmy.shantae.SHA512.SHA512;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class HashController
{
    @FXML private TextArea inputArea;
    @FXML private TextArea outputArea256;
    @FXML private TextArea outputArea512;
    @FXML private TextArea compareArea;
    @FXML private TextArea eduArea;
    @FXML private CheckBox educationalBox;
    @FXML private Label    compareResultLabel;

    // ── Menu ─────────────────────────────────────────────────────────────────

    @FXML
    private void onImport()
    {
        File file = chooseFile("Import input file");
        if (file == null) return;
        try {
            inputArea.setText(Files.readString(file.toPath(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            showError("Cannot read file: " + e.getMessage());
        }
    }

    @FXML
    private void onExport()
    {
        String result = outputArea256.getText().trim();
        if (result.isEmpty()) { showError("Nothing to export."); return; }
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export hashes");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text files", "*.txt"));
        File file = chooser.showSaveDialog(null);
        if (file == null) return;
        try {
            String content = "SHA-256: " + outputArea256.getText() + "\n"
                           + "SHA-512: " + outputArea512.getText() + "\n";
            Files.writeString(file.toPath(), content, StandardCharsets.UTF_8);
        } catch (IOException e) {
            showError("Export failed: " + e.getMessage());
        }
    }

    // ── Buttons ───────────────────────────────────────────────────────────────

    @FXML
    private void onBrowseFile()
    {
        File file = chooseFile("Select file to hash");
        if (file == null) return;
        try {
            byte[] bytes = Files.readAllBytes(file.toPath());
            inputArea.setText("[File: " + file.getName() + "  " + bytes.length + " bytes]");
            outputArea256.setText(SHA256.hash(bytes));
            outputArea512.setText(SHA512.hash(bytes));
            eduArea.clear();
        } catch (IOException e) {
            showError("Cannot read file: " + e.getMessage());
        }
    }

    @FXML
    private void onHash()
    {
        String text = inputArea.getText();
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);

        outputArea512.setText(SHA512.hash(bytes));
        outputArea256.setText(SHA256.hash(bytes));
    }

    @FXML
    private void onCopy256()
    {
        copyToClipboard(outputArea256.getText().trim());
    }

    @FXML
    private void onCopy512()
    {
        copyToClipboard(outputArea512.getText().trim());
    }

    @FXML
    private void onCompare()
    {
        String pasted = compareArea.getText().trim();
        if (pasted.isEmpty()) { compareResultLabel.setText("Paste a hash first."); return; }

        // match against whichever length fits
        boolean match256 = outputArea256.getText().trim().equalsIgnoreCase(pasted);
        boolean match512 = outputArea512.getText().trim().equalsIgnoreCase(pasted);

        if (match256 || match512) {
            compareResultLabel.setStyle("-fx-text-fill: green;");
            compareResultLabel.setText("✓  MATCH  (" + (match256 ? "SHA-256" : "SHA-512") + ")");
        } else {
            compareResultLabel.setStyle("-fx-text-fill: red;");
            compareResultLabel.setText("✗  MISMATCH");
        }
    }

    @FXML
    private void onEducationalToggle()
    {
        eduArea.setVisible(educationalBox.isSelected());
    }

    @FXML
    private void onClear()
    {
        inputArea.clear();
        outputArea256.clear();
        outputArea512.clear();
        compareArea.clear();
        eduArea.clear();
        compareResultLabel.setText("");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void copyToClipboard(String text)
    {
        if (text.isEmpty()) return;
        ClipboardContent content = new ClipboardContent();
        content.putString(text);
        Clipboard.getSystemClipboard().setContent(content);
    }

    private File chooseFile(String title)
    {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);

        return chooser.showOpenDialog(null);
    }

    private void showError(String msg)
    {
        outputArea256.setText("Error: " + msg);
    }
}
