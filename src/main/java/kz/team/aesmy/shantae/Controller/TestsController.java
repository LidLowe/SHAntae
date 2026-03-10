package kz.team.aesmy.shantae.Controller;

import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import javafx.stage.FileChooser;
import kz.team.aesmy.shantae.HMAC.HMAC;
import kz.team.aesmy.shantae.PBKDF2.PBKDF2;
import kz.team.aesmy.shantae.SHA256.SHA256;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;

public class TestsController
{
    @FXML private TextArea resultsArea;

    private final SecureRandom rng = new SecureRandom();

    // ── Menu ──────────────────────────────────────────────────────────────────

    @FXML
    private void onExport()
    {
        String text = resultsArea.getText();
        if (text.isEmpty()) return;
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Export results");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Text files", "*.txt"));
        File file = chooser.showSaveDialog(null);
        if (file == null) return;
        try {
            Files.writeString(file.toPath(), text, StandardCharsets.UTF_8);
        } catch (IOException e) {
            append("Export failed: " + e.getMessage());
        }
    }

    // ── Run all ───────────────────────────────────────────────────────────────

    @FXML private void onRunAllTests()
    {
        resultsArea.clear();
        onCollision();
        onAvalanche();
        onFileIntegrity();
        onHmacVerify();
        onPasswordStorage();
        onDifferentSalts();
    }

    @FXML private void onRunAllBench()
    {
        resultsArea.clear();
        onBenchSHA256();
        onBenchHMAC();
        onBenchPBKDF2();
        onBenchFileHash();
    }

    // ═════════════════════════════════════════════════════════════════════════
    // FUNCTIONAL TESTS
    // ═════════════════════════════════════════════════════════════════════════

    // Test 9 — Collision Resistance
    @FXML
    private void onCollision()
    {
        appendHeader("Test 9 — Collision Resistance");

        String[] inputs = {
            "hello",
            "Hello",
            "hello ",
            "world",
            "SHA-256",
            ""
        };

        boolean allDifferent = true;
        String[] hashes = new String[inputs.length];

        for (int i = 0; i < inputs.length; i++) {
            hashes[i] = SHA256.hash(inputs[i].getBytes(StandardCharsets.UTF_8));
            append(String.format("  %-10s → %s", "\"" + inputs[i] + "\"", hashes[i]));
        }

        // check all hashes are unique
        for (int i = 0; i < hashes.length; i++)
            for (int j = i + 1; j < hashes.length; j++)
                if (hashes[i].equals(hashes[j])) { allDifferent = false; }

        appendResult(allDifferent, "All " + inputs.length + " different inputs produced unique hashes");
    }

    // Test 10 — Avalanche Effect
    @FXML
    private void onAvalanche()
    {
        appendHeader("Test 10 — Avalanche Effect");

        // original message as bytes
        byte[] original = "avalanche test input".getBytes(StandardCharsets.UTF_8);
        String hashA    = SHA256.hash(original);

        // flip exactly 1 bit in the first byte
        byte[] flipped    = Arrays.copyOf(original, original.length);
        flipped[0]       ^= 0x01;
        String hashB      = SHA256.hash(flipped);

        int changedBits   = countDifferentBits(hashA, hashB);
        int totalBits     = 256;
        double percentage = (changedBits / (double) totalBits) * 100.0;

        append("  Original input : \"" + new String(original, StandardCharsets.UTF_8) + "\"");
        append("  Flipped bit 0  : \"" + new String(flipped,  StandardCharsets.UTF_8) + "\"");
        append("  Hash A : " + hashA);
        append("  Hash B : " + hashB);
        append(String.format("  Changed bits   : %d / %d  (%.1f%%)", changedBits, totalBits, percentage));

        // avalanche passes if ~40-60% of bits changed
        boolean pass = percentage >= 40.0 && percentage <= 60.0;
        appendResult(pass, String.format("%.1f%% of bits changed (expected ~50%%)", percentage));
    }

    // Test 11 — File Integrity
    @FXML
    private void onFileIntegrity()
    {
        appendHeader("Test 11 — File Integrity");
        try {
            // create a temp file
            File tmp = File.createTempFile("shantae_test_", ".txt");
            tmp.deleteOnExit();
            String content = "This is a test file for integrity checking.";
            Files.writeString(tmp.toPath(), content, StandardCharsets.UTF_8);

            // hash original
            byte[] originalBytes = Files.readAllBytes(tmp.toPath());
            String hashOriginal  = SHA256.hash(originalBytes);
            append("  Original hash : " + hashOriginal);

            // verify unmodified — should match
            byte[] readBack  = Files.readAllBytes(tmp.toPath());
            String hashReadBack = SHA256.hash(readBack);
            boolean unmodifiedOk = hashOriginal.equalsIgnoreCase(hashReadBack);
            appendResult(unmodifiedOk, "Unmodified file hash matches");

            // tamper the file
            Files.writeString(tmp.toPath(), content + " TAMPERED", StandardCharsets.UTF_8);
            byte[] tamperedBytes = Files.readAllBytes(tmp.toPath());
            String hashTampered  = SHA256.hash(tamperedBytes);
            append("  Tampered hash : " + hashTampered);

            boolean tamperedDetected = !hashOriginal.equalsIgnoreCase(hashTampered);
            appendResult(tamperedDetected, "Tampered file detected (hashes differ)");

        } catch (IOException e) {
            append("  ERROR: " + e.getMessage());
        }
    }

    // Test 12 — HMAC Verification
    @FXML
    private void onHmacVerify()
    {
        appendHeader("Test 12 — HMAC Verification");

        byte[] key     = "secret-key".getBytes(StandardCharsets.UTF_8);
        byte[] message = "authentic message".getBytes(StandardCharsets.UTF_8);

        String validTag = HMAC.hash(key, message);
        append("  Key     : \"secret-key\"");
        append("  Message : \"authentic message\"");
        append("  Tag     : " + validTag);

        // valid tag — should be accepted
        String recomputed   = HMAC.hash(key, message);
        boolean validPass   = validTag.equalsIgnoreCase(recomputed);
        appendResult(validPass, "Valid tag accepted");

        // invalid tag — should be rejected
        String fakeTag      = validTag.substring(0, validTag.length() - 2) + "ff";
        boolean invalidPass = !fakeTag.equalsIgnoreCase(recomputed);
        append("  Fake tag: " + fakeTag);
        appendResult(invalidPass, "Invalid tag rejected");

        // wrong key — should be rejected
        byte[] wrongKey   = "wrong-key".getBytes(StandardCharsets.UTF_8);
        String wrongTag   = HMAC.hash(wrongKey, message);
        boolean wrongPass = !wrongTag.equalsIgnoreCase(validTag);
        append("  Wrong key tag: " + wrongTag);
        appendResult(wrongPass, "Wrong key produces different tag");
    }

    // Test 13 — Password Storage
    @FXML
    private void onPasswordStorage()
    {
        appendHeader("Test 13 — Password Storage");

        String password  = "MySecurePassword123!";
        byte[] salt      = new byte[16];
        rng.nextBytes(salt);

        byte[] hash1 = PBKDF2.hashBytes(
                password.getBytes(StandardCharsets.UTF_8), salt, 100_000, 32);
        byte[] hash2 = PBKDF2.hashBytes(
                password.getBytes(StandardCharsets.UTF_8), salt, 100_000, 32);

        append("  Password : \"" + password + "\"");
        append("  Salt     : " + bytesToHex(salt));
        append("  Hash 1   : " + bytesToHex(hash1));
        append("  Hash 2   : " + bytesToHex(hash2));

        // same password + same salt → same hash (deterministic)
        boolean deterministicPass = Arrays.equals(hash1, hash2);
        appendResult(deterministicPass, "Same password + salt produces same hash (deterministic)");

        // wrong password → different hash
        byte[] wrongHash = PBKDF2.hashBytes(
                "WrongPassword".getBytes(StandardCharsets.UTF_8), salt, 100_000, 32);
        boolean wrongPass = !Arrays.equals(hash1, wrongHash);
        appendResult(wrongPass, "Wrong password produces different hash");
    }

    // Test 14 — Different Salts
    @FXML
    private void onDifferentSalts()
    {
        appendHeader("Test 14 — Different Salts");

        String password = "samepassword";
        byte[] salt1    = new byte[16];
        byte[] salt2    = new byte[16];
        rng.nextBytes(salt1);
        rng.nextBytes(salt2);

        // ensure salts are actually different (astronomically unlikely to collide)
        while (Arrays.equals(salt1, salt2)) rng.nextBytes(salt2);

        byte[] hash1 = PBKDF2.hashBytes(
                password.getBytes(StandardCharsets.UTF_8), salt1, 100_000, 32);
        byte[] hash2 = PBKDF2.hashBytes(
                password.getBytes(StandardCharsets.UTF_8), salt2, 100_000, 32);

        append("  Password : \"" + password + "\"");
        append("  Salt 1   : " + bytesToHex(salt1));
        append("  Salt 2   : " + bytesToHex(salt2));
        append("  Hash 1   : " + bytesToHex(hash1));
        append("  Hash 2   : " + bytesToHex(hash2));

        boolean pass = !Arrays.equals(hash1, hash2);
        appendResult(pass, "Same password with different salts produces different hashes");
    }

    // ═════════════════════════════════════════════════════════════════════════
    // PERFORMANCE BENCHMARKS
    // ═════════════════════════════════════════════════════════════════════════

    // Benchmark: SHA-256 speed (MB/s)
    @FXML
    private void onBenchSHA256()
    {
        appendHeader("Benchmark — SHA-256 Speed");

        int[]  sizes   = { 1, 10, 100, 1_000 };   // KB
        int    repeats = 100;

        for (int kb : sizes) {
            byte[] data = new byte[kb * 1024];
            rng.nextBytes(data);

            // warm up
            for (int i = 0; i < 5; i++) SHA256.hash(data);

            long start = System.nanoTime();
            for (int i = 0; i < repeats; i++) SHA256.hash(data);
            long elapsed = System.nanoTime() - start;

            double totalMB  = (kb / 1024.0) * repeats;
            double seconds  = elapsed / 1_000_000_000.0;
            double mbPerSec = totalMB / seconds;

            append(String.format("  %6d KB × %d reps  →  %8.2f MB/s  (%d ms total)",
                    kb, repeats, mbPerSec, elapsed / 1_000_000));
        }
    }

    // Benchmark: HMAC speed
    @FXML
    private void onBenchHMAC()
    {
        appendHeader("Benchmark — HMAC-SHA256 Speed");

        byte[] key  = new byte[32];
        rng.nextBytes(key);

        int[]  sizes   = { 1, 10, 100 };   // KB
        int    repeats = 100;

        for (int kb : sizes) {
            byte[] data = new byte[kb * 1024];
            rng.nextBytes(data);

            // warm up
            for (int i = 0; i < 5; i++) HMAC.hashBytes(key, data);

            long start = System.nanoTime();
            for (int i = 0; i < repeats; i++) HMAC.hashBytes(key, data);
            long elapsed = System.nanoTime() - start;

            double totalMB  = (kb / 1024.0) * repeats;
            double seconds  = elapsed / 1_000_000_000.0;
            double mbPerSec = totalMB / seconds;

            append(String.format("  %6d KB × %d reps  →  %8.2f MB/s  (%d ms total)",
                    kb, repeats, mbPerSec, elapsed / 1_000_000));
        }
    }

    // Benchmark: PBKDF2 100k iterations
    @FXML
    private void onBenchPBKDF2()
    {
        appendHeader("Benchmark — PBKDF2 (100,000 iterations)");

        byte[] password = "benchmarkpassword".getBytes(StandardCharsets.UTF_8);
        byte[] salt     = new byte[16];
        rng.nextBytes(salt);

        int[] iterCounts = { 10_000, 50_000, 100_000 };

        for (int iters : iterCounts) {
            long start   = System.nanoTime();
            PBKDF2.hashBytes(password, salt, iters, 32);
            long elapsed = System.nanoTime() - start;

            append(String.format("  %,7d iterations  →  %d ms", iters, elapsed / 1_000_000));
        }

        append("  (100,000 iterations is the recommended minimum for password hashing)");
    }

    // Benchmark: file hashing speed
    @FXML
    private void onBenchFileHash()
    {
        appendHeader("Benchmark — File Hashing Speed");

        int[] sizes = { 64, 256, 1024, 4096 };  // KB

        for (int kb : sizes) {
            byte[] data  = new byte[kb * 1024];
            rng.nextBytes(data);

            // write to temp file
            try {
                File tmp = File.createTempFile("shantae_bench_", ".bin");
                tmp.deleteOnExit();
                Files.write(tmp.toPath(), data);

                long start   = System.nanoTime();
                byte[] bytes = Files.readAllBytes(tmp.toPath());
                SHA256.hash(bytes);
                long elapsed = System.nanoTime() - start;

                double mb       = kb / 1024.0;
                double seconds  = elapsed / 1_000_000_000.0;
                double mbPerSec = mb / seconds;

                append(String.format("  %5d KB  →  %8.2f MB/s  (%d ms)",
                        kb, mbPerSec, elapsed / 1_000_000));

            } catch (IOException e) {
                append("  ERROR for " + kb + " KB: " + e.getMessage());
            }
        }
    }

    // ═════════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═════════════════════════════════════════════════════════════════════════

    @FXML
    private void onClear() { resultsArea.clear(); }

    private void appendHeader(String title)
    {
        resultsArea.appendText("\n┌─ " + title + "\n");
    }

    private void appendResult(boolean pass, String description)
    {
        String icon = pass ? "✓ PASS" : "✗ FAIL";
        resultsArea.appendText("  " + icon + "  —  " + description + "\n");
    }

    private void append(String line)
    {
        resultsArea.appendText(line + "\n");
    }

    // count differing bits between two hex strings
    private int countDifferentBits(String hexA, String hexB)
    {
        byte[] a = hexToBytes(hexA);
        byte[] b = hexToBytes(hexB);
        int count = 0;
        for (int i = 0; i < a.length; i++)
            count += Integer.bitCount((a[i] ^ b[i]) & 0xFF);
        return count;
    }

    private byte[] hexToBytes(String hex)
    {
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++)
            result[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        return result;
    }

    private String bytesToHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }
}
