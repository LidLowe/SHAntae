package kz.team.aesmy.shantae.HKDF;

import kz.team.aesmy.shantae.HMAC.HMAC;

import java.nio.charset.StandardCharsets;

public class HKDF
{
    private static final int HASH_LEN = 32;

    public static String hash(String inputKeyMaterial, String salt, String info, int okmLenBytes)
    {
        return hash(
                inputKeyMaterial.getBytes(StandardCharsets.UTF_8),
                salt.getBytes(StandardCharsets.UTF_8),
                info.getBytes(StandardCharsets.UTF_8),
                okmLenBytes
        );
    }

    public static String hash(byte[] inputKeyMaterial, byte[] salt, byte[] info, int okmLenBytes)
    {
        return toHexString(hashBytes(inputKeyMaterial, salt, info, okmLenBytes));
    }

    public static byte[] hashBytes(byte[] inputKeyMaterial, byte[] salt, byte[] info, int okmLenBytes)
    {
        byte[] prk = extract(salt, inputKeyMaterial);

        return expand(prk, info, okmLenBytes);
    }

    public static byte[] extract(byte[] salt, byte[] inputKeyMaterial)
    {
        if (salt == null || salt.length == 0)
        {
            salt = new byte[HASH_LEN];
        }

        return HMAC.hashBytes(salt, inputKeyMaterial);
    }

    public static byte[] expand(byte[] prk, byte[] info, int okmLenBytes)
    {
        int n = (okmLenBytes + HASH_LEN - 1) / HASH_LEN;
        byte[] okm = new byte[n * HASH_LEN];
        byte[] tPrev = new byte[0];

        for (int i = 1; i <= n; i++)
        {
            byte[] input = concat(tPrev, info, new byte[]{ (byte) i });
            tPrev = HMAC.hashBytes(prk, input);
            System.arraycopy(tPrev, 0, okm, (i - 1) * HASH_LEN, HASH_LEN);
        }

        if (okm.length != okmLenBytes)
        {
            byte[] trimmed = new byte[okmLenBytes];
            System.arraycopy(okm, 0, trimmed, 0, okmLenBytes);
            return trimmed;
        }

        return okm;
    }

    private static byte[] concat(byte[] a, byte[] b, byte[] c)
    {
        byte[] result = new byte[a.length + b.length + c.length];

        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        System.arraycopy(c, 0, result, a.length + b.length, c.length);

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