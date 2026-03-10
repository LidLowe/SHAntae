package kz.team.aesmy.shantae.Controller;

import javafx.fxml.FXML;
import javafx.scene.control.CheckBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.stage.FileChooser;
import kz.team.aesmy.shantae.HMAC.HMAC;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class HmacController
{
    @FXML private TextArea keyArea;
    @FXML private CheckBox hexKeyBox;
    @FXML private TextArea messageArea;
    @FXML private TextArea tagArea;
    @FXML private Label    verifyLabel;

    @FXML
    private void onImport()
    {
        File file = chooseFile("Import message file");
        if (file == null) return;
        try {
            messageArea.setText(Files.readString(file.toPath(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            showError("Cannot read file: " + e.getMessage());
        }
    }

    @FXML
    private void onExport()
    {
        String tag = tagArea.getText().trim();
        if (tag.isEmpty()) { showError("No tag to export."); return; }

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export HMAC tag");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text files", "*.txt"));
        File file = chooser.showSaveDialog(null);
        if (file == null) return;
        try {
            Files.writeString(file.toPath(), tag, StandardCharsets.UTF_8);
        } catch (IOException e) {
            showError("Export failed: " + e.getMessage());
        }
    }

    @FXML
    private void onBrowseFile()
    {
        File file = chooseFile("Select message file");
        if (file == null) return;
        try {
            messageArea.setText(Files.readString(file.toPath(), StandardCharsets.UTF_8));
        } catch (IOException e) {
            showError("Cannot read file: " + e.getMessage());
        }
    }

    @FXML
    private void onGenerate()
    {
        byte[] keyBytes = resolveKey();
        if (keyBytes == null) return;

        String message = messageArea.getText();
        if (message.isEmpty()) { showError("Message is empty."); return; }

        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
        String tag = HMAC.hash(keyBytes, msgBytes);
        tagArea.setText(tag);
        verifyLabel.setText("");
    }

    @FXML
    private void onVerify()
    {
        byte[] keyBytes = resolveKey();
        if (keyBytes == null) return;

        String message = messageArea.getText();
        if (message.isEmpty()) { showError("Message is empty."); return; }

        String pastedTag = tagArea.getText().trim();
        if (pastedTag.isEmpty()) { showError("Paste the tag to verify."); return; }

        byte[] msgBytes  = message.getBytes(StandardCharsets.UTF_8);
        String computed  = HMAC.hash(keyBytes, msgBytes);

        if (computed.equalsIgnoreCase(pastedTag)) {
            verifyLabel.setStyle("-fx-text-fill: green;");
            verifyLabel.setText("✓  VALID");
        } else {
            verifyLabel.setStyle("-fx-text-fill: red;");
            verifyLabel.setText("✗  INVALID");
        }
    }

    @FXML
    private void onCopy()
    {
        String tag = tagArea.getText().trim();
        if (tag.isEmpty()) return;
        ClipboardContent content = new ClipboardContent();
        content.putString(tag);
        Clipboard.getSystemClipboard().setContent(content);
    }

    @FXML
    private void onClear()
    {
        keyArea.clear();
        messageArea.clear();
        tagArea.clear();
        verifyLabel.setText("");
    }

    private byte[] resolveKey()
    {
        String keyText = keyArea.getText().trim();
        if (keyText.isEmpty()) { showError("Key is empty."); return null; }

        if (hexKeyBox.isSelected()) {
            // strip spaces and validate
            keyText = keyText.replaceAll("\\s+", "");
            if (keyText.length() % 2 != 0 || !keyText.matches("[0-9a-fA-F]+")) {
                showError("Invalid hex key."); return null;
            }
            return hexToBytes(keyText);
        }

        return keyText.getBytes(StandardCharsets.UTF_8);
    }

    private byte[] hexToBytes(String hex)
    {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++)
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return result;
    }

    private File chooseFile(String title)
    {
        FileChooser chooser = new FileChooser();
        chooser.setTitle(title);
        return chooser.showOpenDialog(null);
    }

    private void showError(String msg)
    {
        verifyLabel.setStyle("-fx-text-fill: red;");
        verifyLabel.setText("Error: " + msg);
    }
}
