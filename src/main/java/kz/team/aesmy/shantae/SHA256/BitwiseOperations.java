package kz.team.aesmy.shantae.SHA256;

public class BitwiseOperations
{
    /**
     *  The right shift operation
     *  SHR^n(x) = x >> n
     */
    private static int shr(int x, int n)
    {
        return x >>> n;
    }

    /**
     *  The rotate right (circular right shift) operation
     *  ROTR^n(x) = (x >> n) OR (x << w - n)
     */
    private static int rotr(int x, int n)
    {
        return (x >>> n) | (x << (32- n));
    }

    /**
     *  Choose function
     *  Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
     */
    public static int ch(int x, int y, int z)
    {
        return (x & y) ^ (~x & z);
    }

    /**
     *  Majority function
     *  Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
     */
    public static int maj(int x, int y, int z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     *  Σ₀(x) = ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)
     */
    public static int bigSigma0(int x)
    {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }

    /**
     *  Σ₁(x) = ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)
     */
    public static int bigSigma1(int x)
    {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }

    /**
     *  σ₀(x) = ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)
     */
    public static int smallSigma0(int x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
    }

    /**
     *  σ₁(x) = ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)
     */
    public static int smallSigma1(int x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
    }
}