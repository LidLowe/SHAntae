package kz.team.aesmy.shantae.HMAC;

import kz.team.aesmy.shantae.SHA256.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class HMAC
{
    private static final int BLOCK_SIZE = 64;

    public static String hash(String key, String message)
    {
        return hash(
                key.getBytes(StandardCharsets.UTF_8),
                message.getBytes(StandardCharsets.UTF_8)
        );
    }

    public static String hash(byte[] keyBytes, byte[] messageBytes)
    {
        return toHexString(hashBytes(keyBytes, messageBytes));
    }

    public static byte[] hashBytes(byte[] keyBytes, byte[] messageBytes)
    {
        byte[] k = normalizeKey(keyBytes);

        byte[] iKeyPad = xorPad(k, 0x36);
        byte[] oKeyPad = xorPad(k, 0x5C);

        byte[] innerHash = SHA256.hashBytes(concat(iKeyPad, messageBytes));

        return SHA256.hashBytes(concat(oKeyPad, innerHash));
    }

    private static byte[] normalizeKey(byte[] keyBytes)
    {
        if (keyBytes.length > BLOCK_SIZE)
        {
            keyBytes = SHA256.hashBytes(keyBytes);
        }

        return Arrays.copyOf(keyBytes, BLOCK_SIZE);
    }

    private static byte[] xorPad(byte[] key, int pad)
    {
        byte[] result = new byte[BLOCK_SIZE];

        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            result[i] = (byte)(key[i] ^ pad);
        }

        return result;
    }

    public static byte[] concat(byte[] a, byte[] b)
    {
        byte[] result = new byte[a.length + b.length];

        System.arraycopy(a, 0, result, 0,        a.length);
        System.arraycopy(b, 0, result, a.length, b.length);

        return result;
    }

    private static String toHexString(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes)
        {
            sb.append(String.format("%02x", b & 0xFF));
        }

        return sb.toString();
    }
}