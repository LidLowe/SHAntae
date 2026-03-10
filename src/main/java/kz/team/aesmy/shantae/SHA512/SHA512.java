package kz.team.aesmy.shantae.SHA512;

import java.nio.charset.StandardCharsets;

import static kz.team.aesmy.shantae.SHA512.BitwiseOperations.*;
import static kz.team.aesmy.shantae.SHA512.Constants.*;

public class SHA512
{
    public static String hash(String message)
    {
        return hash(message.getBytes(StandardCharsets.UTF_8));
    }

    public static String hash(byte[] messageBytes)
    {
        long[] padded = padding(messageBytes);
        long[] digest = compress(padded);

        return toHexString(digest);
    }

    private static long[] padding(byte[] msgBytes)
    {
        long bitLen = (long) msgBytes.length * 8;
        int totalBytes = ((msgBytes.length + 17 + 127) / 128) * 128;
        long[] padded = new long[totalBytes / 8];

        for (int i = 0; i < msgBytes.length; i++)
        {
            padded[i / 8] |= (long) (msgBytes[i] & 0xFF) << (56 - (i % 8) * 8);
        }

        padded[msgBytes.length / 8] |= 0x80L << (56 - (msgBytes.length % 8) * 8);

        padded[padded.length - 2] = 0L;
        padded[padded.length - 1] = bitLen;

        return padded;
    }

    private static long[] compress(long[] padded)
    {
        long[] h = H.clone();

        for (int i = 0; i < padded.length; i += 16)
        {
            long[] w = new long[80];
            System.arraycopy(padded, i, w, 0, 16);

            for (int t = 16; t < 80; t++)
            {
                w[t] = smallSigma1(w[t - 2]) + w[t - 7] + smallSigma0(w[t - 15]) + w[t - 16];
            }

            long a = h[0], b = h[1], c = h[2], d = h[3],
                 e = h[4], f = h[5], g = h[6], hVal = h[7];

            for (int t = 0; t < 80; t++)
            {
                long t1 = hVal + bigSigma1(e) + ch(e, f, g) + K[t] + w[t];
                long t2 = bigSigma0(a) + maj(a, b, c);
                hVal = g; g = f; f = e; e = d + t1;
                d = c;    c = b; b = a; a = t1 + t2;
            }

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hVal;
        }

        return h;
    }

    private static String toHexString(long[] hash)
    {
        StringBuilder sb = new StringBuilder();

        for (long val : hash)
        {
            sb.append(String.format("%016x", val));
        }

        return sb.toString();
    }
}