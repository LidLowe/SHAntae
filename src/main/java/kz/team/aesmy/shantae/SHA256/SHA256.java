package kz.team.aesmy.shantae.SHA256;

public class SHA256
{
    private final String message;

    public SHA256(String message)
    {
        this.message = message;
    }

    private int[] padding()
    {
        int length = message.length() * 8;
    }
}
