package kz.team.aesmy.shantae.SHA256;

import java.nio.charset.StandardCharsets;

import static kz.team.aesmy.shantae.SHA256.BitwiseOperations.*;
import static kz.team.aesmy.shantae.SHA256.Constants.*;

public class SHA256
{
    public String hash(String message)
    {
        int[] padded = padding(message);
        int[] h = H.clone();

        for (int i = 0; i < padded.length; i += 16)
        {
            int[] w = new int[64];
            System.arraycopy(padded, i, w, 0, 16);

            for (int t = 16; t < 64; t++)
            {
                w[t] = smallSigma1(w[t - 2]) + w[t - 7] + smallSigma0(w[t - 15]) + w[t - 16];
            }

            int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hVal = h[7];

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

            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += hVal;
        }

        return toHexString(h);
    }

    private int[] padding(String message)
    {
        byte[] msgBytes = message.getBytes(StandardCharsets.UTF_8);
        long bitLen = (long) msgBytes.length * 8;

        int totalBytes = ((msgBytes.length + 9 + 63) / 64) * 64;
        int[] padded = new int[totalBytes / 4];

        for (int i = 0; i < msgBytes.length; i++)
        {
            padded[i / 4] |= (msgBytes[i] & 0xFF) << (24 - (i % 4) * 8);
        }

        padded[msgBytes.length / 4] |= 0x80 << (24 - (msgBytes.length % 4) * 8);

        padded[padded.length - 2] = (int) (bitLen >>> 32);
        padded[padded.length - 1] = (int) bitLen;

        return padded;
    }

    private String toHexString(int[] hashArray)
    {
        StringBuilder sb = new StringBuilder();

        for (int val : hashArray)
        {
            sb.append(String.format("%08x", val));
        }

        return sb.toString();
    }
}