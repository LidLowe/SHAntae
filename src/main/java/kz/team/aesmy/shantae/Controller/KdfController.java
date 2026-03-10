package kz.team.aesmy.shantae.Controller;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.stage.FileChooser;
import kz.team.aesmy.shantae.HKDF.HKDF;
import kz.team.aesmy.shantae.PBKDF2.PBKDF2;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ResourceBundle;

public class KdfController implements Initializable
{
    @FXML private ChoiceBox<String> modeChoice;

    @FXML private TextArea inputArea;
    @FXML private TextArea saltArea;
    @FXML private TextArea infoArea;
    @FXML private TextArea outputArea;

    @FXML private Label   infoLabel;
    @FXML private Label   iterLabel;

    @FXML private Spinner<Integer> iterationsSpinner;
    @FXML private Spinner<Integer> keyLenSpinner;

    private final SecureRandom rng = new SecureRandom();

    // ── Init ──────────────────────────────────────────────────────────────────

    @Override
    public void initialize(URL url, ResourceBundle rb)
    {
        modeChoice.getItems().addAll("PBKDF2", "HKDF");
        modeChoice.setValue("PBKDF2");

        iterationsSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 10_000_000, 100_000, 10_000));
        keyLenSpinner.setValueFactory(
                new SpinnerValueFactory.IntegerSpinnerValueFactory(1, 512, 32, 4));

        applyMode("PBKDF2");
    }

    // ── Menu ──────────────────────────────────────────────────────────────────

    @FXML
    private void onExport()
    {
        String output = outputArea.getText().trim();
        if (output.isEmpty()) return;

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export derived key");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text files", "*.txt"));
        File file = chooser.showSaveDialog(null);
        if (file == null) return;
        try {
            Files.writeString(file.toPath(), output, StandardCharsets.UTF_8);
        } catch (IOException e) {
            outputArea.setText("Export failed: " + e.getMessage());
        }
    }

    // ── Buttons ───────────────────────────────────────────────────────────────

    @FXML
    private void onModeChange()
    {
        applyMode(modeChoice.getValue());
    }

    @FXML
    private void onRandomSalt()
    {
        byte[] salt = new byte[16];
        rng.nextBytes(salt);
        saltArea.setText(bytesToHex(salt));
    }

    @FXML
    private void onDerive()
    {
        String input = inputArea.getText().trim();
        String salt  = saltArea.getText().trim();

        if (input.isEmpty()) { outputArea.setText("Error: input is empty."); return; }

        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        byte[] saltBytes  = salt.isEmpty()
                ? new byte[0]
                : salt.getBytes(StandardCharsets.UTF_8);
        int keyLen = keyLenSpinner.getValue();

        if ("PBKDF2".equals(modeChoice.getValue()))
        {
            int iterations = iterationsSpinner.getValue();
            String derived = PBKDF2.hash(inputBytes, saltBytes, iterations, keyLen);
            outputArea.setText(derived);
        }
        else // HKDF
        {
            String info      = infoArea.getText().trim();
            byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
            String derived   = HKDF.hash(inputBytes, saltBytes, infoBytes, keyLen);
            outputArea.setText(derived);
        }
    }

    @FXML
    private void onCopy()
    {
        String text = outputArea.getText().trim();
        if (text.isEmpty()) return;
        ClipboardContent content = new ClipboardContent();
        content.putString(text);
        Clipboard.getSystemClipboard().setContent(content);
    }

    @FXML
    private void onClear()
    {
        inputArea.clear();
        saltArea.clear();
        infoArea.clear();
        outputArea.clear();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void applyMode(String mode)
    {
        boolean isPbkdf2 = "PBKDF2".equals(mode);

        // show iterations spinner only for PBKDF2
        iterLabel.setVisible(isPbkdf2);
        iterationsSpinner.setVisible(isPbkdf2);

        // show info field only for HKDF
        infoLabel.setVisible(!isPbkdf2);
        infoArea.setVisible(!isPbkdf2);

        // update prompt text
        inputArea.setPromptText(isPbkdf2
                ? "Password"
                : "Input Key Material (IKM)");
        saltArea.setPromptText(isPbkdf2
                ? "Salt (text)"
                : "Salt (text, optional)");
    }

    private String bytesToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}
