package kz.team.aesmy.shantae.Utils;

public class Encoding {

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();
    private static final String BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    public static String bytesToHex(int[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (int b : bytes) {
            sb.append(HEX_CHARS[(b >> 4) & 0x0F]);
            sb.append(HEX_CHARS[b & 0x0F]);
        }
        return sb.toString();
    }

    public static int[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s", "").toLowerCase();
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Invalid hex string length");
        }

        int[] result = new int[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int high = hexCharToInt(hex.charAt(i * 2));
            int low = hexCharToInt(hex.charAt(i * 2 + 1));
            result[i] = (high << 4) | low;
        }
        return result;
    }

    private static int hexCharToInt(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        throw new IllegalArgumentException("Invalid hex character: " + c);
    }

    public static String bytesToBase64(int[] bytes) {
        if (bytes.length == 0) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        int i = 0;

        while (i < bytes.length) {
            int startPos = i;
            int b0 = bytes[i++] & 0xFF;
            int b1 = (i < bytes.length) ? bytes[i++] & 0xFF : 0;
            int b2 = (i < bytes.length) ? bytes[i++] & 0xFF : 0;

            int bytesInGroup = Math.min(3, bytes.length - startPos);

            sb.append(BASE64_CHARS.charAt(b0 >> 2));
            sb.append(BASE64_CHARS.charAt(((b0 & 0x03) << 4) | (b1 >> 4)));

            if (bytesInGroup > 1) {
                sb.append(BASE64_CHARS.charAt(((b1 & 0x0F) << 2) | (b2 >> 6)));
            } else {
                sb.append('=');
            }

            if (bytesInGroup > 2) {
                sb.append(BASE64_CHARS.charAt(b2 & 0x3F));
            } else {
                sb.append('=');
            }
        }

        return sb.toString();
    }

    public static int[] base64ToBytes(String base64) {
        base64 = base64.replaceAll("\\s", "");

        if (base64.isEmpty()) {
            return new int[0];
        }

        int padding = 0;
        if (base64.endsWith("==")) padding = 2;
        else if (base64.endsWith("=")) padding = 1;

        int outputLength = (base64.length() * 3 / 4) - padding;
        int[] result = new int[outputLength];

        int i = 0;
        int resultIndex = 0;

        while (i < base64.length()) {
            int c0 = base64IndexOf(base64.charAt(i++));
            int c1 = base64IndexOf(base64.charAt(i++));
            int c2 = base64IndexOf(base64.charAt(i++));
            int c3 = base64IndexOf(base64.charAt(i++));

            if (resultIndex < outputLength) {
                result[resultIndex++] = ((c0 << 2) | (c1 >> 4)) & 0xFF;
            }
            if (resultIndex < outputLength && c2 != -1) {
                result[resultIndex++] = ((c1 << 4) | (c2 >> 2)) & 0xFF;
            }
            if (resultIndex < outputLength && c3 != -1) {
                result[resultIndex++] = ((c2 << 6) | c3) & 0xFF;
            }
        }

        return result;
    }

    private static int base64IndexOf(char c) {
        if (c == '=') return -1;
        int index = BASE64_CHARS.indexOf(c);
        if (index == -1) {
            throw new IllegalArgumentException("Invalid Base64 character: " + c);
        }
        return index;
    }

    public static int[] stringToBytes(String text) {
        byte[] bytes = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int[] result = new int[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            result[i] = bytes[i] & 0xFF;
        }
        return result;
    }

    public static String bytesToString(int[] bytes) {
        byte[] byteArray = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            byteArray[i] = (byte) bytes[i];
        }
        return new String(byteArray, java.nio.charset.StandardCharsets.UTF_8);
    }
}
