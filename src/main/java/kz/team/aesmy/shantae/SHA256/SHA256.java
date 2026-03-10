package kz.team.aesmy.shantae.SHA256;

import java.nio.charset.StandardCharsets;

import static kz.team.aesmy.shantae.SHA256.BitwiseOperations.*;
import static kz.team.aesmy.shantae.SHA256.Constants.*;

public class SHA256
{
    /**
     *  hash function for pure SHA-256
     */
    public static String hash(String message)
    {
        return hash(message.getBytes(StandardCharsets.UTF_8));
    }

    /**
     *  hash function for HMAC, PBKDF2 and HKDF
     */
    public static String hash(byte[] messageBytes)
    {
        int[] padded = padding(messageBytes);
        int[] digest = compress(padded);
        return toHexString(digest);
    }

    public static byte[] hashBytes(byte[] messageBytes)
    {
        int[] padded = padding(messageBytes);
        int[] digest = compress(padded);
        return intsToBytes(digest);
    }

    private static int[] padding(byte[] msgBytes)
    {
        long bitLen = (long) msgBytes.length * 8;
        int  totalBytes = ((msgBytes.length + 9 + 63) / 64) * 64;
        int[] padded = new int[totalBytes / 4];

        for (int i = 0; i < msgBytes.length; i++)
        {
            padded[i / 4] |= (msgBytes[i] & 0xFF) << (24 - (i % 4) * 8);
        }

        padded[msgBytes.length / 4] |= 0x80 << (24 - (msgBytes.length % 4) * 8);
        padded[padded.length - 2]    = (int)(bitLen >>> 32);
        padded[padded.length - 1]    = (int) bitLen;

        return padded;
    }

    private static int[] compress(int[] padded)
    {
        int[] h = H.clone();

        for (int i = 0; i < padded.length; i += 16)
        {
            int[] w = new int[64];
            System.arraycopy(padded, i, w, 0, 16);

            for (int t = 16; t < 64; t++)
            {
                w[t] = smallSigma1(w[t - 2]) + w[t - 7] + smallSigma0(w[t - 15]) + w[t - 16];
            }

            int a = h[0];
            int b = h[1];
            int c = h[2];
            int d = h[3];
            int e = h[4];
            int f = h[5];
            int g = h[6];
            int hVal = h[7];

            for (int t = 0; t < 64; t++)
            {
                int t1 = hVal + bigSigma1(e) + ch(e, f, g) + K[t] + w[t];
                int t2 = bigSigma0(a) + maj(a, b, c);

                hVal = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            h[0] += a;
            h[1] += b;
            h[2] += c;
            h[3] += d;
            h[4] += e;
            h[5] += f;
            h[6] += g;
            h[7] += hVal;
        }

        return h;
    }

    private static String toHexString(int[] hash)
    {
        StringBuilder sb = new StringBuilder();

        for (int val : hash)
        {
            sb.append(String.format("%08x", val));
        }

        return sb.toString();
    }

    static byte[] intsToBytes(int[] ints)
    {
        byte[] bytes = new byte[ints.length * 4];

        for (int i = 0; i < ints.length; i++)
        {
            bytes[i * 4]     = (byte)(ints[i] >>> 24);
            bytes[i * 4 + 1] = (byte)(ints[i] >>> 16);
            bytes[i * 4 + 2] = (byte)(ints[i] >>> 8);
            bytes[i * 4 + 3] = (byte) ints[i];
        }

        return bytes;
    }
}