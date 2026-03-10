package kz.team.aesmy.shantae.Controller;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.ArrayList;
import java.util.List;

public class ManifestStore
{
    public record Entry(String filePath, String hashHex) {}

    public void write(Path manifestPath, List<Entry> entries) throws IOException
    {
        StringBuilder sb = new StringBuilder("[\n");

        for (int i = 0; i < entries.size(); i++)
        {
            Entry e = entries.get(i);
            sb.append(String.format("  {\"path\":\"%s\",\"hash\":\"%s\"}",
                    escape(e.filePath()), e.hashHex()));

            if (i < entries.size() - 1)
            {
                sb.append(",");
            }

            sb.append("\n");
        }

        sb.append("]\n");
        Files.writeString(manifestPath, sb.toString(), StandardCharsets.UTF_8);
    }

    public List<Entry> read(Path manifestPath) throws IOException
    {
        List<Entry> entries = new ArrayList<>();

        for (String line : Files.readAllLines(manifestPath, StandardCharsets.UTF_8))
        {
            line = line.trim();

            if (line.isEmpty() || line.equals("[") || line.equals("]"))
            {
                continue;
            }
            if (line.endsWith(","))
            {
                line = line.substring(0, line.length() - 1);
            }

            Entry e = parseLine(line);

            if (e != null)
            {
                entries.add(e);
            }
        }

        return entries;
    }

    private Entry parseLine(String json)
    {
        try {
            String path = extractField(json, "path");
            String hash = extractField(json, "hash");

            if (path == null || hash == null)
            {
                return null;
            }

            return new Entry(path, hash);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    private String extractField(String json, String field)
    {
        String key = "\"" + field + "\":\"";
        int start = json.indexOf(key);

        if (start < 0)
        {
            return null;
        }

        start += key.length();
        int end = json.indexOf("\"", start);

        return end < 0 ? null : json.substring(start, end);
    }

    private String escape(String s)
    {
        return s.replace("\\", "/").replace("\"", "\\\"");
    }
}