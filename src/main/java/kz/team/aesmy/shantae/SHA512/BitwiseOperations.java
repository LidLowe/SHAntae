package kz.team.aesmy.shantae.SHA512;

public class BitwiseOperations
{
    /**
     *  The right shift operation
     *  SHR^n(x) = x >> n
     */
    private static long shr(long x, long n)
    {
        return x >>> n;
    }

    /**
     *  The rotate right (circular right shift) operation
     *  ROTR^n(x) = (x >> n) OR (x << 64 - n)
     */
    private static long rotr(long x, long n)
    {
        return (x >>> n) | (x << (64 - n));
    }

    /**
     *  Choose function
     *  Ch(x, y, z) = (x AND y) XOR (NOT x AND z)
     */
    public static long ch(long x, long y, long z)
    {
        return (x & y) ^ (~x & z);
    }

    /**
     *  Majority function
     *  Maj(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
     */
    public static long maj(long x, long y, long z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    /**
     *  Σ₀(x) = ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)
     */
    public static long bigSigma0(long x)
    {
        return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
    }

    /**
     *  Σ₁(x) = ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)
     */
    public static long bigSigma1(long x)
    {
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
    }

    /**
     *  σ₀(x) = ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)
     */
    public static long smallSigma0(long x)
    {
        return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7);
    }

    /**
     *  σ₁(x) = ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)
     */
    public static long smallSigma1(long x)
    {
        return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6);
    }
}