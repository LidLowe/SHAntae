package kz.team.aesmy.shantae.Controller;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.FileChooser;
import kz.team.aesmy.shantae.PBKDF2.PBKDF2;
import kz.team.aesmy.shantae.Controller.PasswordStore;
import kz.team.aesmy.shantae.Controller.PasswordStore.Entry;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.List;
import java.util.ResourceBundle;

public class PasswordController implements Initializable
{
    @FXML private TextField usernameField;
    @FXML private PasswordField passwordField;
    @FXML private TextArea statusArea;
    @FXML private TableView<EntryRow> passwordTable;
    @FXML private TableColumn<EntryRow, String> colUsername;
    @FXML private TableColumn<EntryRow, String> colSalt;
    @FXML private TableColumn<EntryRow, String> colHash;

    private static final int ITERATIONS = 100_000;
    private static final int KEY_LEN = 32;          // 256-bit output
    private static final int SALT_LEN = 16;         // 128-bit salt

    private final PasswordStore store = new PasswordStore();
    private final ObservableList<EntryRow> rows = FXCollections.observableArrayList();
    private final SecureRandom rng = new SecureRandom();

    public static class EntryRow
    {
        private final String username, salt, hash;

        public EntryRow(String u, String s, String h)
        {
            username = u;
            salt = s;
            hash = h;
        }

        public String getUsername()
        {
            return username;
        }

        public String getSalt()
        {
            return salt;
        }

        public String getHash()
        {
            return hash;
        }
    }

    @Override
    public void initialize(URL url, ResourceBundle rb)
    {
        colUsername.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getUsername()));
        colSalt.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getSalt()));
        colHash.setCellValueFactory(data ->
                new javafx.beans.property.SimpleStringProperty(data.getValue().getHash()));

        passwordTable.setItems(rows);
        loadTable();
    }

    @FXML
    private void onExport()
    {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export passwords");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("JSON files", "*.json"));
        File file = chooser.showSaveDialog(null);

        if (file == null)
        {
            return;
        }

        try
        {
            List<Entry> entries = store.loadAll();
            StringBuilder sb = new StringBuilder("[\n");

            for (int i = 0; i < entries.size(); i++)
            {
                Entry e = entries.get(i);
                sb.append(String.format("  {\"username\":\"%s\",\"salt\":\"%s\",\"hash\":\"%s\"}",
                        e.username(), e.saltHex(), e.hashHex()));

                if (i < entries.size() - 1)
                {
                    sb.append(",");
                }

                sb.append("\n");
            }

            sb.append("]\n");

            Files.writeString(file.toPath(), sb.toString(), StandardCharsets.UTF_8);
            setStatus("Exported " + entries.size() + " entries to " + file.getName());
        }
        catch (IOException e)
        {
            setStatus("Export failed: " + e.getMessage());
        }
    }

    @FXML
    private void onImport()
    {
        setStatus("Import: place passwords.json next to the jar and restart.");
    }

    @FXML
    private void onStore()
    {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty())
        {
            setStatus("Error: username is empty.");
            return;
        }
        if (password.isEmpty())
        {
            setStatus("Error: password is empty.");
            return;
        }

        byte[] saltBytes = new byte[SALT_LEN];
        rng.nextBytes(saltBytes);
        String saltHex = bytesToHex(saltBytes);

        byte[] hashBytes = PBKDF2.hashBytes(
                password.getBytes(StandardCharsets.UTF_8),
                saltBytes, ITERATIONS, KEY_LEN);
        String hashHex = bytesToHex(hashBytes);

        try
        {
            store.save(new Entry(username, saltHex, hashHex));
            setStatus("Stored password for \"" + username + "\"  (PBKDF2, " + ITERATIONS + " iterations)");
            usernameField.clear();
            passwordField.clear();
            loadTable();
        }
        catch (IOException e)
        {
            setStatus("Error saving: " + e.getMessage());
        }
    }

    @FXML
    private void onVerify()
    {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isEmpty())
        {
            setStatus("Error: username is empty.");
            return;
        }
        if (password.isEmpty())
        {
            setStatus("Error: password is empty.");
            return;
        }

        List<Entry> all = store.loadAll();
        Entry found = all.stream()
                .filter(e -> e.username().equalsIgnoreCase(username))
                .findFirst().orElse(null);

        if (found == null) {
            setStatus("User \"" + username + "\" not found.");
            return;
        }

        byte[] saltBytes  = hexToBytes(found.saltHex());
        byte[] hashBytes  = PBKDF2.hashBytes(
                password.getBytes(StandardCharsets.UTF_8),
                saltBytes, ITERATIONS, KEY_LEN);
        String computed   = bytesToHex(hashBytes);

        if (computed.equalsIgnoreCase(found.hashHex())) {
            setStatus("✓  Password CORRECT for \"" + username + "\"");
        } else {
            setStatus("✗  Password INCORRECT for \"" + username + "\"");
        }
    }

    @FXML
    private void onDelete()
    {
        EntryRow selected = passwordTable.getSelectionModel().getSelectedItem();
        if (selected == null) { setStatus("Select a row to delete."); return; }
        try {
            store.delete(selected.getUsername());
            setStatus("Deleted entry for \"" + selected.getUsername() + "\"");
            loadTable();
        } catch (IOException e) {
            setStatus("Delete failed: " + e.getMessage());
        }
    }

    private void loadTable()
    {
        rows.clear();
        for (Entry e : store.loadAll())
            rows.add(new EntryRow(e.username(),
                    e.saltHex().substring(0, Math.min(16, e.saltHex().length())) + "…",
                    e.hashHex().substring(0, Math.min(16, e.hashHex().length())) + "…"));
    }

    private void setStatus(String msg)
    {
        statusArea.setText(msg); }

    private String bytesToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    private byte[] hexToBytes(String hex)
    {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++)
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return result;
    }
}
