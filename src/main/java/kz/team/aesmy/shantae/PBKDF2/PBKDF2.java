package kz.team.aesmy.shantae.PBKDF2;

import kz.team.aesmy.shantae.HMAC.HMAC;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class PBKDF2
{
    private static final int HASH_LEN = 32;

    public static String hash(String password, String salt, int iterations, int dkLenBytes)
    {
        return hash(
                password.getBytes(StandardCharsets.UTF_8),
                salt.getBytes(StandardCharsets.UTF_8),
                iterations,
                dkLenBytes
        );
    }

    public static String hash(byte[] password, byte[] salt, int iterations, int dkLenBytes)
    {
        return toHexString(hashBytes(password, salt, iterations, dkLenBytes));
    }

    public static byte[] hashBytes(byte[] password, byte[] salt, int iterations, int dkLenBytes)
    {
        int blockCount = (dkLenBytes + HASH_LEN - 1) / HASH_LEN;
        byte[] dk      = new byte[blockCount * HASH_LEN];

        for (int i = 1; i <= blockCount; i++)
        {
            byte[] block = computeBlock(password, salt, iterations, i);
            System.arraycopy(block, 0, dk, (i - 1) * HASH_LEN, HASH_LEN);
        }

        if (dk.length != dkLenBytes)
        {
            byte[] trimmed = new byte[dkLenBytes];
            System.arraycopy(dk, 0, trimmed, 0, dkLenBytes);
            return trimmed;
        }

        return dk;
    }

    private static byte[] computeBlock(byte[] password, byte[] salt, int iterations, int blockIndex)
    {
        byte[] u = HMAC.hashBytes(password, HMAC.concat(salt, intToBytes(blockIndex)));
        byte[] result = u.clone();

        for (int i = 1; i < iterations; i++)
        {
            u = HMAC.hashBytes(password, u);
            xorInPlace(result, u);
        }

        return result;
    }

    private static void xorInPlace(byte[] target, byte[] source)
    {
        for (int i = 0; i < target.length; i++)
        {
            target[i] ^= source[i];
        }
    }

    private static byte[] intToBytes(int value)
    {
        return ByteBuffer.allocate(4).putInt(value).array();
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