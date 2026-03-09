package kz.team.aesmy.shantae.SHA512;

public class SHA512
{
    private final String message;

    public SHA512(String message)
    {
        this.message = message;
    }

    public long[] padding()
    {
        byte[] msgBytes = message.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int byteLen = msgBytes.length;

        long bitLen = (long) byteLen * 8;

        int totalBytes = ((byteLen + 16) / 128 + 1) * 128;

        long[] paddedArray = new long[totalBytes / 8];

        for (int i = 0; i < byteLen; i++)
        {
            paddedArray[i / 8] |= ((long) (msgBytes[i] & 0xFF)) << (56 - (i % 8) * 8);
        }

        paddedArray[byteLen / 8] |= 0x80L << (56 - (byteLen % 8) * 8);

        paddedArray[paddedArray.length - 1] = bitLen;

        return paddedArray;
    }
}