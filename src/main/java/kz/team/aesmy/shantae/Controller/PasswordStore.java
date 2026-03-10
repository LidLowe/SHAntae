package kz.team.aesmy.shantae.Controller;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class PasswordStore
{
    private static final Path FILE = Path.of("passwords.json");

    public record Entry(String username, String saltHex, String hashHex) {}

    public List<Entry> loadAll()
    {
        List<Entry> entries = new ArrayList<>();
        if (!Files.exists(FILE)) return entries;

        try {
            for (String line : Files.readAllLines(FILE, StandardCharsets.UTF_8)) {
                line = line.trim();
                if (line.isEmpty() || line.equals("[") || line.equals("]")) continue;
                if (line.endsWith(",")) line = line.substring(0, line.length() - 1);
                Entry e = parseLine(line);
                if (e != null) entries.add(e);
            }
        } catch (IOException e) {
            System.err.println("PasswordStore: cannot read file: " + e.getMessage());
        }

        return entries;
    }

    public void save(Entry entry) throws IOException
    {
        List<Entry> all = loadAll();
        all.removeIf(e -> e.username().equalsIgnoreCase(entry.username()));
        all.add(entry);
        writeAll(all);
    }

    public void delete(String username) throws IOException
    {
        List<Entry> all = loadAll();
        all.removeIf(e -> e.username().equalsIgnoreCase(username));
        writeAll(all);
    }

    public boolean contains(String username)
    {
        return loadAll().stream().anyMatch(e -> e.username().equalsIgnoreCase(username));
    }

    private void writeAll(List<Entry> entries) throws IOException
    {
        StringBuilder sb = new StringBuilder("[\n");
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            sb.append("  ")
              .append(toJson(e));
            if (i < entries.size() - 1) sb.append(",");
            sb.append("\n");
        }
        sb.append("]\n");
        Files.writeString(FILE, sb.toString(), StandardCharsets.UTF_8);
    }

    private String toJson(Entry e)
    {
        return String.format("{\"username\":\"%s\",\"salt\":\"%s\",\"hash\":\"%s\"}",
                escape(e.username()), e.saltHex(), e.hashHex());
    }

    // minimal JSON object parser — only handles our own format
    private Entry parseLine(String json)
    {
        try {
            String username = extractField(json, "username");
            String salt     = extractField(json, "salt");
            String hash     = extractField(json, "hash");
            if (username == null || salt == null || hash == null) return null;
            return new Entry(username, salt, hash);
        } catch (Exception e) {
            return null;
        }
    }

    private String extractField(String json, String field)
    {
        String key    = "\"" + field + "\":\"";
        int    start  = json.indexOf(key);
        if (start < 0) return null;
        start += key.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    private String escape(String s)
    {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
