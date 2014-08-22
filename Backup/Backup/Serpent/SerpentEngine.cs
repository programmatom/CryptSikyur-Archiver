// Serpent Block Cipher (AES candidate) bitsliced implementation
// 
// According to http://www.cl.cam.ac.uk/~rja14/serpent.html
// "Serpent is now completely in the public domain, and we impose no restrictions on its use.
// This was announced on the 21st August at the First AES Candidate Conference [http://csrc.nist.gov/encryption/aes/round1/conf1/aes1conf.htm].
// The optimised implementations in the submission package are now under the General Public
// License (GPL), although some comments in the code still say otherwise. You are welcome to
// use Serpent for any application. If you do use it, we would appreciate it if you would let
// us know!"
//
// and, from http://www.cs.technion.ac.il/~biham/Reports/Serpent/
// "Serpent is now completely in the public domain, and we impose no restrictions on its use.
// This was announced on the 21st August 1998 at the AES conference. The OPTIMIZED
// implementations in the above submission package are now under GNU PUBLIC LICENSE (GPL),
// although the comments in the code still say otherwise. You are welcome to use Serpent for
// any application. However, if you do use it, we would appreciate it if you would let us know!"
//
//
// The following file is a C# transliteration of the java-bitsliced implementation of
// the Serpent block cipher algorithm (AES block cipher candidate).
//
// Original source was obtained from:
// http://www.cl.cam.ac.uk/~rja14/serpent.html
// Specifically, the AES competition submission package:
// http://www.cl.cam.ac.uk/~rja14/Papers/serpent.tar.gz
//
// The specific file in the package was:
// serpent.tar.gz\floppy3\src\Serpent\Serpent_BitSlice.java
//
// The changes made were the minimum required to convert from java to C#. In particular:
// 1. Replace the java zero-fill right shift operator:
//           x >>> y
//    with an unsigned integer right shift appropriate for C#:
//           (int)((uint)x >> y)
// 2. Replace a number of java diagnostic references with C# equivalent, for example:
//           System.out.println()
//    becomes
//           Console.WriteLine()
// 3. Packaging, language syntax (e.g. final to static or const), and other trivial changes.
//
//
// ************** BEGIN serpent.tar.gz\floppy3\src\Serpent\Serpent_BitSlice.java **************
// $Id: $
//
// $Log: $
// Revision 1.2  1998/05/2  Serpent authors
// + further performance improvement by new gate circuits
// + and other changes
//
// Revision 1.1.3  1998/04/14  raif
// + further performance improvement by reducing multi-dim array references.
// + performance improvement by inlining function calls.
// + added code to generate Intermediate Values KAT.
// + cosmetics.
//
// Revision 1.1  1998/04/07  Serpent authors
// + revised slightly (endianness, and key schedule for variable lengths)
//
// Revision 1.0  1998/04/06  raif
// + start of history.
//
// $Endlog$
/*
 * Copyright (c) 1997, 1998 Systemics Ltd on behalf of
 * the Cryptix Development Team. All rights reserved.
 */
using System;
using System.IO;

namespace Serpent
{
//...........................................................................
/**
 * A bit-slice implementation in Java of the Serpent cipher.<p>
 *
 * Serpent is a 128-bit 32-round block cipher with variable key lengths,
 * including 128-, 192- and 256-bit
 * keys conjectured to be at least as secure as three-key triple-DES.<p>
 *
 * Serpent was designed by Ross Anderson, Eli Biham and Lars Knudsen as a
 * candidate algorithm for the NIST AES Quest.<p>
 *
 * References:<ol>
 *  <li>Serpent: A New Block Cipher Proposal. This paper was published in the
 *  proceedings of the "Fast Software Encryption Workshop No. 5" held in
 *  Paris in March 1998. LNCS, Springer Verlag.<p>
 *  <li>Reference implementation of the standard Serpent cipher written in C
 *  by <a href="http://www.cl.cam.ac.uk/~fms/"> Frank Stajano</a>.</ol><p>
 *
 * <b>Copyright</b> &copy; 1997, 1998
 * <a href="http://www.systemics.com/">Systemics Ltd</a> on behalf of the
 * <a href="http://www.systemics.com/docs/cryptix/">Cryptix Development Team</a>.
 * <br>All rights reserved.<p>
 *
 * <b>$Revision: $</b>
 * @author  Raif S. Naffah
 * @author  Serpent authors (Ross Anderson, Eli Biham and Lars Knudsen)
 */
public static class Serpent_BitSlice // implicit no-argument constructor
{
// Debugging methods and variables
//...........................................................................

    const String NAME = "Serpent_BitSlice";
    const bool IN = true, OUT = false;

    static bool DEBUG = false; //Serpent_Properties.GLOBAL_DEBUG;
    static int debuglevel =
        DEBUG ? Int32.MaxValue/*Serpent_Properties.getLevel("Serpent_Algorithm")*/ : 0;
    static TextWriter err =
        DEBUG ? Console.Out/*Serpent_Properties.getOutput()*/ : null;

    static bool TRACE =
        false;//Serpent_Properties.isTraceable("Serpent_Algorithm");

    static void debug (String s) { err.WriteLine(">>> "+NAME+": "+s); }
    static void trace (bool _in, String s) {
        if (TRACE) err.WriteLine((_in?"==> ":"<== ")+NAME+"."+s);
    }
    static void trace (String s) { if (TRACE) err.WriteLine("<=> "+NAME+"."+s); }


// Constants and variables
//...........................................................................

    public const int BLOCK_SIZE =  16; // bytes in a data-block

    const int ROUNDS = 32;              // nbr of rounds
    const int PHI = unchecked((int)0x9E3779B9); // (sqrt(5) - 1) * 2**31

    /**
     * An array of 32 (number of rounds) S boxes.<p>
     *
     * An S box is an array of 16 distinct quantities, each in the range 0-15.
     * A value v at position p for a given S box, implies that if this S box
     * is given on input a value p, it will return the value v.
     */
    static readonly byte[][] Sbox = new byte[][] {
	new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } /* S7: */
    };

    static readonly byte[][] SboxInverse = new byte[][] {
	new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } /* InvS7: */
    };

    private static readonly char[] HEX_DIGITS = new char[] {
        '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'
    };


// Basic API methods
//...........................................................................

    /**
     * Expand a user-supplied key material into a session key.
     *
     * @param key  The user-key bytes (multiples of 4) to use.
     * @exception  InvalidKeyException  If the key is invalid.
     */
    public static Object makeKey (byte[] key)
{
if (DEBUG) trace(IN, "makeKey("+key+")");
if (DEBUG && debuglevel > 7) {
Console.WriteLine("Intermediate Bit-slice Session Key Values");
Console.WriteLine();
Console.WriteLine("Raw="+toString(key));
}
        // compute prekeys w[]:
        // (a) from user key material
        int[] w = new int[4 * (ROUNDS + 1)];
        int limit = key.Length / 4;
        int i, j, t, offset = 0;
        for (i = 0; i < limit; i++)
            w[i] = (key[offset++] & 0xFF) |
                   (key[offset++] & 0xFF) <<  8 |
                   (key[offset++] & 0xFF) << 16 |
                   (key[offset++] & 0xFF) << 24;

        if (i < 8)
            w[i++] = 1;
//        for (; i < 8; i++)
//            w[i] = 0;

        // (b) and expanding them to full 132 x 32-bit material
        // this is a literal implementation of the Serpent paper
        // (section 4 The Key Schedule, p.226)
        //
        // start by computing the first 8 values using the second
        // lot of 8 values as an intermediary buffer
        for (i = 8, j = 0; i < 16; i++) {
            t = w[j] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ j++;
            w[i] = t << 11 | (int)((uint)t >> 21);
        }
        // translate the buffer by -8
        for (i = 0, j = 8; i < 8; ) w[i++] = w[j++];
        limit = 4 * (ROUNDS + 1); // 132 for a 32-round Serpent
        // finish computing the remaining intermediary subkeys
        for ( ; i < limit; i++) {
            t = w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ PHI ^ i;
            w[i] = t << 11 | (int)((uint)t >> 21);
        }
        // compute intermediary key. use the same array as prekeys
        int x0, x1, x2, x3, y0, y1, y2, y3, z;
        byte[] sb;
        for (i = 0; i < ROUNDS + 1; i++) {
            x0 = w[4*i    ];
            x1 = w[4*i + 1];
            x2 = w[4*i + 2];
            x3 = w[4*i + 3];
            y0 = y1 = y2 = y3 = 0;
            sb = Sbox[(ROUNDS + 3 - i) % ROUNDS];
            for (j = 0; j < 32; j++) {
                z = sb[(((uint)x0 >> j) & 0x01)      |
                       (((uint)x1 >> j) & 0x01) << 1 |
                       (((uint)x2 >> j) & 0x01) << 2 |
                       (((uint)x3 >> j) & 0x01) << 3];
                y0 |= ( z        & 0x01) << j;
                y1 |= ((int)((uint)z >> 1) & 0x01) << j;
                y2 |= ((int)((uint)z >> 2) & 0x01) << j;
                y3 |= ((int)((uint)z >> 3) & 0x01) << j;
            }
            w[4*i    ] = y0;
            w[4*i + 1] = y1;
            w[4*i + 2] = y2;
            w[4*i + 3] = y3;
        }
        // instead of a 2-dim array use a 1-dim array for better preformance
if (DEBUG && debuglevel > 7) {
Console.WriteLine("K[]:"); for(i=0;i<ROUNDS+1;i++){for(j=0;j<4;j++) Console.Write("0x"+intToString(w[i*4+j])+", "); Console.WriteLine();}
Console.WriteLine();
}
if (DEBUG) trace(OUT, "makeKey()");
        return w;
    }

    /**
     * Encrypt exactly one block of plaintext.
     *
     * @param  in         The plaintext.
     * @param  inOffset   Index of in from which to start considering data.
     * @param  sessionKey The session key to use for encryption.
     * @return The ciphertext generated from a plaintext using the session key.
     */
    public static byte[]
    blockEncrypt (byte[] _in, int inOffset, Object sessionKey) {
if (DEBUG) trace(IN, "blockEncrypt("+_in+", "+inOffset+", "+sessionKey+")");
        int[] K = (int[]) sessionKey;
        int x0 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int x1 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int x2 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int x3 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int y0, y1, y2, y3, z;
	int t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10;
	int t11, t12, t13, t14, t15, t16, t17, t18, t19;

	x0 ^=  K[ 0*4+0];
	x1 ^=  K[ 0*4+1];
	x2 ^=  K[ 0*4+2];
	x3 ^=  K[ 0*4+3] ;

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */

	t01 = x1  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  ^ x1 ;
	y3  = t02 ^ t01;
	t05 = x2  | y3 ;
	t06 = x0  ^ x3 ;
	t07 = x1  | x2 ;
	t08 = x3  & t05;
	t09 = t03 & t07;
	y2  = t09 ^ t08;
	t11 = t09 & y2 ;
	t12 = x2  ^ x3 ;
	t13 = t07 ^ t11;
	t14 = x1  & t06;
	t15 = t06 ^ t13;
	y0  =     ~ t15;
	t17 = y0  ^ t14;
	y1  = t12 ^ t17;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 1*4+0];
	x1 ^=  K[ 1*4+1];
	x2 ^=  K[ 1*4+2];
	x3 ^=  K[ 1*4+3] ;

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */

	t01 = x0  | x3 ;
	t02 = x2  ^ x3 ;
	t03 =     ~ x1 ;
	t04 = x0  ^ x2 ;
	t05 = x0  | t03;
	t06 = x3  & t04;
	t07 = t01 & t02;
	t08 = x1  | t06;
	y2  = t02 ^ t05;
	t10 = t07 ^ t08;
	t11 = t01 ^ t10;
	t12 = y2  ^ t11;
	t13 = x1  & x3 ;
	y3  =     ~ t10;
	y1  = t13 ^ t12;
	t16 = t10 | y1 ;
	t17 = t05 & t16;
	y0  = x2  ^ t17;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 2*4+0];
	x1 ^=  K[ 2*4+1];
	x2 ^=  K[ 2*4+2];
	x3 ^=  K[ 2*4+3] ;

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */

	t01 = x0  | x2 ;
	t02 = x0  ^ x1 ;
	t03 = x3  ^ t01;
	y0  = t02 ^ t03;
	t05 = x2  ^ y0 ;
	t06 = x1  ^ t05;
	t07 = x1  | t05;
	t08 = t01 & t06;
	t09 = t03 ^ t07;
	t10 = t02 | t09;
	y1  = t10 ^ t08;
	t12 = x0  | x3 ;
	t13 = t09 ^ y1 ;
	t14 = x1  ^ t13;
	y3  =     ~ t09;
	y2  = t12 ^ t14;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 3*4+0];
	x1 ^=  K[ 3*4+1];
	x2 ^=  K[ 3*4+2];
	x3 ^=  K[ 3*4+3] ;

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */

	t01 = x0  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  & x3 ;
	t04 = t01 & t02;
	t05 = x1  | t03;
	t06 = x0  & x1 ;
	t07 = x3  ^ t04;
	t08 = x2  | t06;
	t09 = x1  ^ t07;
	t10 = x3  & t05;
	t11 = t02 ^ t10;
	y3  = t08 ^ t09;
	t13 = x3  | y3 ;
	t14 = x0  | t07;
	t15 = x1  & t13;
	y2  = t08 ^ t11;
	y0  = t14 ^ t15;
	y1  = t05 ^ t04;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 4*4+0];
	x1 ^=  K[ 4*4+1];
	x2 ^=  K[ 4*4+2];
	x3 ^=  K[ 4*4+3] ;

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */

	t01 = x0  | x1 ;
	t02 = x1  | x2 ;
	t03 = x0  ^ t02;
	t04 = x1  ^ x3 ;
	t05 = x3  | t03;
	t06 = x3  & t01;
	y3  = t03 ^ t06;
	t08 = y3  & t04;
	t09 = t04 & t05;
	t10 = x2  ^ t06;
	t11 = x1  & x2 ;
	t12 = t04 ^ t08;
	t13 = t11 | t03;
	t14 = t10 ^ t09;
	t15 = x0  & t05;
	t16 = t11 | t12;
	y2  = t13 ^ t08;
	y1  = t15 ^ t16;
	y0  =     ~ t14;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 5*4+0];
	x1 ^=  K[ 5*4+1];
	x2 ^=  K[ 5*4+2];
	x3 ^=  K[ 5*4+3] ;

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */

	t01 = x1  ^ x3 ;
	t02 = x1  | x3 ;
	t03 = x0  & t01;
	t04 = x2  ^ t02;
	t05 = t03 ^ t04;
	y0  =     ~ t05;
	t07 = x0  ^ t01;
	t08 = x3  | y0 ;
	t09 = x1  | t05;
	t10 = x3  ^ t08;
	t11 = x1  | t07;
	t12 = t03 | y0 ;
	t13 = t07 | t10;
	t14 = t01 ^ t11;
	y2  = t09 ^ t13;
	y1  = t07 ^ t08;
	y3  = t12 ^ t14;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 6*4+0];
	x1 ^=  K[ 6*4+1];
	x2 ^=  K[ 6*4+2];
	x3 ^=  K[ 6*4+3] ;

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */

	t01 = x0  & x3 ;
	t02 = x1  ^ x2 ;
	t03 = x0  ^ x3 ;
	t04 = t01 ^ t02;
	t05 = x1  | x2 ;
	y1  =     ~ t04;
	t07 = t03 & t05;
	t08 = x1  & y1 ;
	t09 = x0  | x2 ;
	t10 = t07 ^ t08;
	t11 = x1  | x3 ;
	t12 = x2  ^ t11;
	t13 = t09 ^ t10;
	y2  =     ~ t13;
	t15 = y1  & t03;
	y3  = t12 ^ t07;
	t17 = x0  ^ x1 ;
	t18 = y2  ^ t15;
	y0  = t17 ^ t18;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 7*4+0];
	x1 ^=  K[ 7*4+1];
	x2 ^=  K[ 7*4+2];
	x3 ^=  K[ 7*4+3] ;

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */

	t01 = x0  & x2 ;
	t02 =     ~ x3 ;
	t03 = x0  & t02;
	t04 = x1  | t01;
	t05 = x0  & x1 ;
	t06 = x2  ^ t04;
	y3  = t03 ^ t06;
	t08 = x2  | y3 ;
	t09 = x3  | t05;
	t10 = x0  ^ t08;
	t11 = t04 & y3 ;
	y1  = t09 ^ t10;
	t13 = x1  ^ y1 ;
	t14 = t01 ^ y1 ;
	t15 = x2  ^ t05;
	t16 = t11 | t13;
	t17 = t02 | t14;
	y0  = t15 ^ t17;
	y2  = x0  ^ t16;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 8*4+0];
	x1 ^=  K[ 8*4+1];
	x2 ^=  K[ 8*4+2];
	x3 ^=  K[ 8*4+3] ;

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */

	t01 = x1  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  ^ x1 ;
	y3  = t02 ^ t01;
	t05 = x2  | y3 ;
	t06 = x0  ^ x3 ;
	t07 = x1  | x2 ;
	t08 = x3  & t05;
	t09 = t03 & t07;
	y2  = t09 ^ t08;
	t11 = t09 & y2 ;
	t12 = x2  ^ x3 ;
	t13 = t07 ^ t11;
	t14 = x1  & t06;
	t15 = t06 ^ t13;
	y0  =     ~ t15;
	t17 = y0  ^ t14;
	y1  = t12 ^ t17;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[ 9*4+0];
	x1 ^=  K[ 9*4+1];
	x2 ^=  K[ 9*4+2];
	x3 ^=  K[ 9*4+3] ;

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */

	t01 = x0  | x3 ;
	t02 = x2  ^ x3 ;
	t03 =     ~ x1 ;
	t04 = x0  ^ x2 ;
	t05 = x0  | t03;
	t06 = x3  & t04;
	t07 = t01 & t02;
	t08 = x1  | t06;
	y2  = t02 ^ t05;
	t10 = t07 ^ t08;
	t11 = t01 ^ t10;
	t12 = y2  ^ t11;
	t13 = x1  & x3 ;
	y3  =     ~ t10;
	y1  = t13 ^ t12;
	t16 = t10 | y1 ;
	t17 = t05 & t16;
	y0  = x2  ^ t17;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[10*4+0];
	x1 ^=  K[10*4+1];
	x2 ^=  K[10*4+2];
	x3 ^=  K[10*4+3] ;

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */

	t01 = x0  | x2 ;
	t02 = x0  ^ x1 ;
	t03 = x3  ^ t01;
	y0  = t02 ^ t03;
	t05 = x2  ^ y0 ;
	t06 = x1  ^ t05;
	t07 = x1  | t05;
	t08 = t01 & t06;
	t09 = t03 ^ t07;
	t10 = t02 | t09;
	y1  = t10 ^ t08;
	t12 = x0  | x3 ;
	t13 = t09 ^ y1 ;
	t14 = x1  ^ t13;
	y3  =     ~ t09;
	y2  = t12 ^ t14;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[11*4+0];
	x1 ^=  K[11*4+1];
	x2 ^=  K[11*4+2];
	x3 ^=  K[11*4+3] ;

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */

	t01 = x0  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  & x3 ;
	t04 = t01 & t02;
	t05 = x1  | t03;
	t06 = x0  & x1 ;
	t07 = x3  ^ t04;
	t08 = x2  | t06;
	t09 = x1  ^ t07;
	t10 = x3  & t05;
	t11 = t02 ^ t10;
	y3  = t08 ^ t09;
	t13 = x3  | y3 ;
	t14 = x0  | t07;
	t15 = x1  & t13;
	y2  = t08 ^ t11;
	y0  = t14 ^ t15;
	y1  = t05 ^ t04;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[12*4+0];
	x1 ^=  K[12*4+1];
	x2 ^=  K[12*4+2];
	x3 ^=  K[12*4+3] ;

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */

	t01 = x0  | x1 ;
	t02 = x1  | x2 ;
	t03 = x0  ^ t02;
	t04 = x1  ^ x3 ;
	t05 = x3  | t03;
	t06 = x3  & t01;
	y3  = t03 ^ t06;
	t08 = y3  & t04;
	t09 = t04 & t05;
	t10 = x2  ^ t06;
	t11 = x1  & x2 ;
	t12 = t04 ^ t08;
	t13 = t11 | t03;
	t14 = t10 ^ t09;
	t15 = x0  & t05;
	t16 = t11 | t12;
	y2  = t13 ^ t08;
	y1  = t15 ^ t16;
	y0  =     ~ t14;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[13*4+0];
	x1 ^=  K[13*4+1];
	x2 ^=  K[13*4+2];
	x3 ^=  K[13*4+3] ;

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */

	t01 = x1  ^ x3 ;
	t02 = x1  | x3 ;
	t03 = x0  & t01;
	t04 = x2  ^ t02;
	t05 = t03 ^ t04;
	y0  =     ~ t05;
	t07 = x0  ^ t01;
	t08 = x3  | y0 ;
	t09 = x1  | t05;
	t10 = x3  ^ t08;
	t11 = x1  | t07;
	t12 = t03 | y0 ;
	t13 = t07 | t10;
	t14 = t01 ^ t11;
	y2  = t09 ^ t13;
	y1  = t07 ^ t08;
	y3  = t12 ^ t14;

	x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
	x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
	x1  =   y1  ^   x0  ^   x2 ;
	x3  =   y3  ^   x2  ^ (x0)<<3;
	x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
	x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
	x0  =   x0  ^   x1  ^   x3 ;
	x2  =   x2  ^   x3  ^ (x1 <<7);
	x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
	x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
	x0 ^=  K[14*4+0];
	x1 ^=  K[14*4+1];
	x2 ^=  K[14*4+2];
	x3 ^=  K[14*4+3] ;

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */

	t01 = x0  & x3 ;
	t02 = x1  ^ x2 ;
	t03 = x0  ^ x3 ;
	t04 = t01 ^ t02;
	t05 = x1  | x2 ;
	y1  =     ~ t04;
	t07 = t03 & t05;
	t08 = x1  & y1 ;
	t09 = x0  | x2 ;
	t10 = t07 ^ t08;
	t11 = x1  | x3 ;
	t12 = x2  ^ t11;
	t13 = t09 ^ t10;
	y2  =     ~ t13;
	t15 = y1  & t03;
	y3  = t12 ^ t07;
	t17 = x0  ^ x1 ;
	t18 = y2  ^ t15;
	y0  = t17 ^ t18;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[15*4+0];
  x1 ^=  K[15*4+1];
  x2 ^=  K[15*4+2];
  x3 ^=  K[15*4+3] ;

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */

	t01 = x0  & x2 ;
	t02 =     ~ x3 ;
	t03 = x0  & t02;
	t04 = x1  | t01;
	t05 = x0  & x1 ;
	t06 = x2  ^ t04;
	y3  = t03 ^ t06;
	t08 = x2  | y3 ;
	t09 = x3  | t05;
	t10 = x0  ^ t08;
	t11 = t04 & y3 ;
	y1  = t09 ^ t10;
	t13 = x1  ^ y1 ;
	t14 = t01 ^ y1 ;
	t15 = x2  ^ t05;
	t16 = t11 | t13;
	t17 = t02 | t14;
	y0  = t15 ^ t17;
	y2  = x0  ^ t16;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[16*4+0];
  x1 ^=  K[16*4+1];
  x2 ^=  K[16*4+2];
  x3 ^=  K[16*4+3] ;

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */

	t01 = x1  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  ^ x1 ;
	y3  = t02 ^ t01;
	t05 = x2  | y3 ;
	t06 = x0  ^ x3 ;
	t07 = x1  | x2 ;
	t08 = x3  & t05;
	t09 = t03 & t07;
	y2  = t09 ^ t08;
	t11 = t09 & y2 ;
	t12 = x2  ^ x3 ;
	t13 = t07 ^ t11;
	t14 = x1  & t06;
	t15 = t06 ^ t13;
	y0  =     ~ t15;
	t17 = y0  ^ t14;
	y1  = t12 ^ t17;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[17*4+0];
  x1 ^=  K[17*4+1];
  x2 ^=  K[17*4+2];
  x3 ^=  K[17*4+3] ;

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */

	t01 = x0  | x3 ;
	t02 = x2  ^ x3 ;
	t03 =     ~ x1 ;
	t04 = x0  ^ x2 ;
	t05 = x0  | t03;
	t06 = x3  & t04;
	t07 = t01 & t02;
	t08 = x1  | t06;
	y2  = t02 ^ t05;
	t10 = t07 ^ t08;
	t11 = t01 ^ t10;
	t12 = y2  ^ t11;
	t13 = x1  & x3 ;
	y3  =     ~ t10;
	y1  = t13 ^ t12;
	t16 = t10 | y1 ;
	t17 = t05 & t16;
	y0  = x2  ^ t17;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[18*4+0];
  x1 ^=  K[18*4+1];
  x2 ^=  K[18*4+2];
  x3 ^=  K[18*4+3] ;

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */

	t01 = x0  | x2 ;
	t02 = x0  ^ x1 ;
	t03 = x3  ^ t01;
	y0  = t02 ^ t03;
	t05 = x2  ^ y0 ;
	t06 = x1  ^ t05;
	t07 = x1  | t05;
	t08 = t01 & t06;
	t09 = t03 ^ t07;
	t10 = t02 | t09;
	y1  = t10 ^ t08;
	t12 = x0  | x3 ;
	t13 = t09 ^ y1 ;
	t14 = x1  ^ t13;
	y3  =     ~ t09;
	y2  = t12 ^ t14;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[19*4+0];
  x1 ^=  K[19*4+1];
  x2 ^=  K[19*4+2];
  x3 ^=  K[19*4+3] ;

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */

	t01 = x0  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  & x3 ;
	t04 = t01 & t02;
	t05 = x1  | t03;
	t06 = x0  & x1 ;
	t07 = x3  ^ t04;
	t08 = x2  | t06;
	t09 = x1  ^ t07;
	t10 = x3  & t05;
	t11 = t02 ^ t10;
	y3  = t08 ^ t09;
	t13 = x3  | y3 ;
	t14 = x0  | t07;
	t15 = x1  & t13;
	y2  = t08 ^ t11;
	y0  = t14 ^ t15;
	y1  = t05 ^ t04;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[20*4+0];
  x1 ^=  K[20*4+1];
  x2 ^=  K[20*4+2];
  x3 ^=  K[20*4+3] ;

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */

	t01 = x0  | x1 ;
	t02 = x1  | x2 ;
	t03 = x0  ^ t02;
	t04 = x1  ^ x3 ;
	t05 = x3  | t03;
	t06 = x3  & t01;
	y3  = t03 ^ t06;
	t08 = y3  & t04;
	t09 = t04 & t05;
	t10 = x2  ^ t06;
	t11 = x1  & x2 ;
	t12 = t04 ^ t08;
	t13 = t11 | t03;
	t14 = t10 ^ t09;
	t15 = x0  & t05;
	t16 = t11 | t12;
	y2  = t13 ^ t08;
	y1  = t15 ^ t16;
	y0  =     ~ t14;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[21*4+0];
  x1 ^=  K[21*4+1];
  x2 ^=  K[21*4+2];
  x3 ^=  K[21*4+3] ;

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */

	t01 = x1  ^ x3 ;
	t02 = x1  | x3 ;
	t03 = x0  & t01;
	t04 = x2  ^ t02;
	t05 = t03 ^ t04;
	y0  =     ~ t05;
	t07 = x0  ^ t01;
	t08 = x3  | y0 ;
	t09 = x1  | t05;
	t10 = x3  ^ t08;
	t11 = x1  | t07;
	t12 = t03 | y0 ;
	t13 = t07 | t10;
	t14 = t01 ^ t11;
	y2  = t09 ^ t13;
	y1  = t07 ^ t08;
	y3  = t12 ^ t14;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[22*4+0];
  x1 ^=  K[22*4+1];
  x2 ^=  K[22*4+2];
  x3 ^=  K[22*4+3] ;

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */

	t01 = x0  & x3 ;
	t02 = x1  ^ x2 ;
	t03 = x0  ^ x3 ;
	t04 = t01 ^ t02;
	t05 = x1  | x2 ;
	y1  =     ~ t04;
	t07 = t03 & t05;
	t08 = x1  & y1 ;
	t09 = x0  | x2 ;
	t10 = t07 ^ t08;
	t11 = x1  | x3 ;
	t12 = x2  ^ t11;
	t13 = t09 ^ t10;
	y2  =     ~ t13;
	t15 = y1  & t03;
	y3  = t12 ^ t07;
	t17 = x0  ^ x1 ;
	t18 = y2  ^ t15;
	y0  = t17 ^ t18;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[23*4+0];
  x1 ^=  K[23*4+1];
  x2 ^=  K[23*4+2];
  x3 ^=  K[23*4+3] ;

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */

	t01 = x0  & x2 ;
	t02 =     ~ x3 ;
	t03 = x0  & t02;
	t04 = x1  | t01;
	t05 = x0  & x1 ;
	t06 = x2  ^ t04;
	y3  = t03 ^ t06;
	t08 = x2  | y3 ;
	t09 = x3  | t05;
	t10 = x0  ^ t08;
	t11 = t04 & y3 ;
	y1  = t09 ^ t10;
	t13 = x1  ^ y1 ;
	t14 = t01 ^ y1 ;
	t15 = x2  ^ t05;
	t16 = t11 | t13;
	t17 = t02 | t14;
	y0  = t15 ^ t17;
	y2  = x0  ^ t16;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[24*4+0];
  x1 ^=  K[24*4+1];
  x2 ^=  K[24*4+2];
  x3 ^=  K[24*4+3] ;

/* S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 */

/* depth = 5,7,4,2, Total gates=18 */

	t01 = x1  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  ^ x1 ;
	y3  = t02 ^ t01;
	t05 = x2  | y3 ;
	t06 = x0  ^ x3 ;
	t07 = x1  | x2 ;
	t08 = x3  & t05;
	t09 = t03 & t07;
	y2  = t09 ^ t08;
	t11 = t09 & y2 ;
	t12 = x2  ^ x3 ;
	t13 = t07 ^ t11;
	t14 = x1  & t06;
	t15 = t06 ^ t13;
	y0  =     ~ t15;
	t17 = y0  ^ t14;
	y1  = t12 ^ t17;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[25*4+0];
  x1 ^=  K[25*4+1];
  x2 ^=  K[25*4+2];
  x3 ^=  K[25*4+3] ;

/* S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 */

/* depth = 10,7,3,5, Total gates=18 */

	t01 = x0  | x3 ;
	t02 = x2  ^ x3 ;
	t03 =     ~ x1 ;
	t04 = x0  ^ x2 ;
	t05 = x0  | t03;
	t06 = x3  & t04;
	t07 = t01 & t02;
	t08 = x1  | t06;
	y2  = t02 ^ t05;
	t10 = t07 ^ t08;
	t11 = t01 ^ t10;
	t12 = y2  ^ t11;
	t13 = x1  & x3 ;
	y3  =     ~ t10;
	y1  = t13 ^ t12;
	t16 = t10 | y1 ;
	t17 = t05 & t16;
	y0  = x2  ^ t17;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[26*4+0];
  x1 ^=  K[26*4+1];
  x2 ^=  K[26*4+2];
  x3 ^=  K[26*4+3] ;

/* S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 */

/* depth = 3,8,11,7, Total gates=16 */

	t01 = x0  | x2 ;
	t02 = x0  ^ x1 ;
	t03 = x3  ^ t01;
	y0  = t02 ^ t03;
	t05 = x2  ^ y0 ;
	t06 = x1  ^ t05;
	t07 = x1  | t05;
	t08 = t01 & t06;
	t09 = t03 ^ t07;
	t10 = t02 | t09;
	y1  = t10 ^ t08;
	t12 = x0  | x3 ;
	t13 = t09 ^ y1 ;
	t14 = x1  ^ t13;
	y3  =     ~ t09;
	y2  = t12 ^ t14;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[27*4+0];
  x1 ^=  K[27*4+1];
  x2 ^=  K[27*4+2];
  x3 ^=  K[27*4+3] ;

/* S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 */

/* depth = 8,3,5,5, Total gates=18 */

	t01 = x0  ^ x2 ;
	t02 = x0  | x3 ;
	t03 = x0  & x3 ;
	t04 = t01 & t02;
	t05 = x1  | t03;
	t06 = x0  & x1 ;
	t07 = x3  ^ t04;
	t08 = x2  | t06;
	t09 = x1  ^ t07;
	t10 = x3  & t05;
	t11 = t02 ^ t10;
	y3  = t08 ^ t09;
	t13 = x3  | y3 ;
	t14 = x0  | t07;
	t15 = x1  & t13;
	y2  = t08 ^ t11;
	y0  = t14 ^ t15;
	y1  = t05 ^ t04;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[28*4+0];
  x1 ^=  K[28*4+1];
  x2 ^=  K[28*4+2];
  x3 ^=  K[28*4+3] ;

/* S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 */

/* depth = 6,7,5,3, Total gates=19 */

	t01 = x0  | x1 ;
	t02 = x1  | x2 ;
	t03 = x0  ^ t02;
	t04 = x1  ^ x3 ;
	t05 = x3  | t03;
	t06 = x3  & t01;
	y3  = t03 ^ t06;
	t08 = y3  & t04;
	t09 = t04 & t05;
	t10 = x2  ^ t06;
	t11 = x1  & x2 ;
	t12 = t04 ^ t08;
	t13 = t11 | t03;
	t14 = t10 ^ t09;
	t15 = x0  & t05;
	t16 = t11 | t12;
	y2  = t13 ^ t08;
	y1  = t15 ^ t16;
	y0  =     ~ t14;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[29*4+0];
  x1 ^=  K[29*4+1];
  x2 ^=  K[29*4+2];
  x3 ^=  K[29*4+3] ;

/* S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 */

/* depth = 4,6,8,6, Total gates=17 */

	t01 = x1  ^ x3 ;
	t02 = x1  | x3 ;
	t03 = x0  & t01;
	t04 = x2  ^ t02;
	t05 = t03 ^ t04;
	y0  =     ~ t05;
	t07 = x0  ^ t01;
	t08 = x3  | y0 ;
	t09 = x1  | t05;
	t10 = x3  ^ t08;
	t11 = x1  | t07;
	t12 = t03 | y0 ;
	t13 = t07 | t10;
	t14 = t01 ^ t11;
	y2  = t09 ^ t13;
	y1  = t07 ^ t08;
	y3  = t12 ^ t14;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[30*4+0];
  x1 ^=  K[30*4+1];
  x2 ^=  K[30*4+2];
  x3 ^=  K[30*4+3] ;

/* S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 */

/* depth = 8,3,6,3, Total gates=19 */

	t01 = x0  & x3 ;
	t02 = x1  ^ x2 ;
	t03 = x0  ^ x3 ;
	t04 = t01 ^ t02;
	t05 = x1  | x2 ;
	y1  =     ~ t04;
	t07 = t03 & t05;
	t08 = x1  & y1 ;
	t09 = x0  | x2 ;
	t10 = t07 ^ t08;
	t11 = x1  | x3 ;
	t12 = x2  ^ t11;
	t13 = t09 ^ t10;
	y2  =     ~ t13;
	t15 = y1  & t03;
	y3  = t12 ^ t07;
	t17 = x0  ^ x1 ;
	t18 = y2  ^ t15;
	y0  = t17 ^ t18;

  x0  = ((((y0))<<(13))| (int)((uint)((y0))>>(32-(13)))) ;
  x2  = ((((y2))<<(3))| (int)((uint)((y2))>>(32-(3)))) ;
  x1  =   y1  ^   x0  ^   x2 ;
  x3  =   y3  ^   x2  ^ (x0)<<3;
  x1  = ((((x1))<<(1))| (int)((uint)((x1))>>(32-(1)))) ;
  x3  = ((((x3))<<(7))| (int)((uint)((x3))>>(32-(7)))) ;
  x0  =   x0  ^   x1  ^   x3 ;
  x2  =   x2  ^   x3  ^ (x1 <<7);
  x0  = ((((x0))<<(5))| (int)((uint)((x0))>>(32-(5)))) ;
  x2  = ((((x2))<<(22))| (int)((uint)((x2))>>(32-(22))))  ;
  x0 ^=  K[31*4+0];
  x1 ^=  K[31*4+1];
  x2 ^=  K[31*4+2];
  x3 ^=  K[31*4+3] ;

/* S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 */

/* depth = 10,7,10,4, Total gates=19 */

	t01 = x0  & x2 ;
	t02 =     ~ x3 ;
	t03 = x0  & t02;
	t04 = x1  | t01;
	t05 = x0  & x1 ;
	t06 = x2  ^ t04;
	y3  = t03 ^ t06;
	t08 = x2  | y3 ;
	t09 = x3  | t05;
	t10 = x0  ^ t08;
	t11 = t04 & y3 ;
	y1  = t09 ^ t10;
	t13 = x1  ^ y1 ;
	t14 = t01 ^ y1 ;
	t15 = x2  ^ t05;
	t16 = t11 | t13;
	t17 = t02 | t14;
	y0  = t15 ^ t17;
	y2  = x0  ^ t16;

  x0 = y0;
  x1 = y1;
  x2 = y2;
  x3 = y3;
  x0 ^=  K[32*4+0];
  x1 ^=  K[32*4+1];
  x2 ^=  K[32*4+2];
  x3 ^=  K[32*4+3] ;


        byte[] result = new byte[] {
            (byte)(x0), (byte)((uint)x0 >> 8), (byte)((uint)x0 >> 16), (byte)((uint)x0 >> 24),
            (byte)(x1), (byte)((uint)x1 >> 8), (byte)((uint)x1 >> 16), (byte)((uint)x1 >> 24),
            (byte)(x2), (byte)((uint)x2 >> 8), (byte)((uint)x2 >> 16), (byte)((uint)x2 >> 24),
            (byte)(x3), (byte)((uint)x3 >> 8), (byte)((uint)x3 >> 16), (byte)((uint)x3 >> 24)
        };
if (DEBUG && debuglevel > 6) {
Console.WriteLine("CT="+toString(result));
Console.WriteLine();
}
if (DEBUG) trace(OUT, "blockEncrypt()");
        return result;
    }

    /**
     * Decrypt exactly one block of ciphertext.
     *
     * @param  in         The ciphertext.
     * @param  inOffset   Index of in from which to start considering data.
     * @param  sessionKey The session key to use for decryption.
     * @return The plaintext generated from a ciphertext using the session key.
     */
    public static byte[]
    blockDecrypt (byte[] _in, int inOffset, Object sessionKey) {
if (DEBUG) trace(IN, "blockDecrypt("+_in+", "+inOffset+", "+sessionKey+")");
        int[] K = (int[]) sessionKey;
        int x0 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int x1 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int x2 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;
        int x3 = (_in[inOffset++] & 0xFF)       |
                 (_in[inOffset++] & 0xFF) <<  8 |
                 (_in[inOffset++] & 0xFF) << 16 |
                 (_in[inOffset++] & 0xFF) << 24;

        int z, y0, y1, y2, y3;
	int t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10;
	int t11, t12, t13, t14, t15, t16, t17, t18, t19;


   x0 ^=  K[32*4+0];  x1 ^=  K[32*4+1];   x2 ^=  K[32*4+2];  x3 ^=  K[32*4+3] ;

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */

	t01 = x0  & x1 ;
	t02 = x0  | x1 ;
	t03 = x2  | t01;
	t04 = x3  & t02;
	y3  = t03 ^ t04;
	t06 = x1  ^ t04;
	t07 = x3  ^ y3 ;
	t08 =     ~ t07;
	t09 = t06 | t08;
	t10 = x1  ^ x3 ;
	t11 = x0  | x3 ;
	y1  = x0  ^ t09;
	t13 = x2  ^ t06;
	t14 = x2  & t11;
	t15 = x3  | y1 ;
	t16 = t01 | t10;
	y0  = t13 ^ t15;
	y2  = t14 ^ t16;

   y0 ^=  K[31*4+0];  y1 ^=  K[31*4+1];   y2 ^=  K[31*4+2];  y3 ^=  K[31*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */

	t01 = x0  ^ x2 ;
	t02 =     ~ x2 ;
	t03 = x1  & t01;
	t04 = x1  | t02;
	t05 = x3  | t03;
	t06 = x1  ^ x3 ;
	t07 = x0  & t04;
	t08 = x0  | t02;
	t09 = t07 ^ t05;
	y1  = t06 ^ t08;
	y0  =     ~ t09;
	t12 = x1  & y0 ;
	t13 = t01 & t05;
	t14 = t01 ^ t12;
	t15 = t07 ^ t13;
	t16 = x3  | t02;
	t17 = x0  ^ y1 ;
	y3  = t17 ^ t15;
	y2  = t16 ^ t14;

   y0 ^=  K[30*4+0];  y1 ^=  K[30*4+1];   y2 ^=  K[30*4+2];  y3 ^=  K[30*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */

	t01 = x0  & x3 ;
	t02 = x2  ^ t01;
	t03 = x0  ^ x3 ;
	t04 = x1  & t02;
	t05 = x0  & x2 ;
	y0  = t03 ^ t04;
	t07 = x0  & y0 ;
	t08 = t01 ^ y0 ;
	t09 = x1  | t05;
	t10 =     ~ x1 ;
	y1  = t08 ^ t09;
	t12 = t10 | t07;
	t13 = y0  | y1 ;
	y3  = t02 ^ t12;
	t15 = t02 ^ t13;
	t16 = x1  ^ x3 ;
	y2  = t16 ^ t15;

   y0 ^=  K[29*4+0];  y1 ^=  K[29*4+1];   y2 ^=  K[29*4+2];  y3 ^=  K[29*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */

	t01 = x1  | x3 ;
	t02 = x2  | x3 ;
	t03 = x0  & t01;
	t04 = x1  ^ t02;
	t05 = x2  ^ x3 ;
	t06 =     ~ t03;
	t07 = x0  & t04;
	y1  = t05 ^ t07;
	t09 = y1  | t06;
	t10 = x0  ^ t07;
	t11 = t01 ^ t09;
	t12 = x3  ^ t04;
	t13 = x2  | t10;
	y3  = t03 ^ t12;
	t15 = x0  ^ t04;
	y2  = t11 ^ t13;
	y0  = t15 ^ t09;

   y0 ^=  K[28*4+0];  y1 ^=  K[28*4+1];   y2 ^=  K[28*4+2];  y3 ^=  K[28*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */

	t01 = x2  | x3 ;
	t02 = x0  | x3 ;
	t03 = x2  ^ t02;
	t04 = x1  ^ t02;
	t05 = x0  ^ x3 ;
	t06 = t04 & t03;
	t07 = x1  & t01;
	y2  = t05 ^ t06;
	t09 = x0  ^ t03;
	y0  = t07 ^ t03;
	t11 = y0  | t05;
	t12 = t09 & t11;
	t13 = x0  & y2 ;
	t14 = t01 ^ t05;
	y1  = x1  ^ t12;
	t16 = x1  | t13;
	y3  = t14 ^ t16;

   y0 ^=  K[27*4+0];  y1 ^=  K[27*4+1];   y2 ^=  K[27*4+2];  y3 ^=  K[27*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */

	t01 = x0  ^ x3 ;
	t02 = x2  ^ x3 ;
	t03 = x0  & x2 ;
	t04 = x1  | t02;
	y0  = t01 ^ t04;
	t06 = x0  | x2 ;
	t07 = x3  | y0 ;
	t08 =     ~ x3 ;
	t09 = x1  & t06;
	t10 = t08 | t03;
	t11 = x1  & t07;
	t12 = t06 & t02;
	y3  = t09 ^ t10;
	y1  = t12 ^ t11;
	t15 = x2  & y3 ;
	t16 = y0  ^ y1 ;
	t17 = t10 ^ t15;
	y2  = t16 ^ t17;

   y0 ^=  K[26*4+0];  y1 ^=  K[26*4+1];   y2 ^=  K[26*4+2];  y3 ^=  K[26*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */

	t01 = x0  ^ x1 ;
	t02 = x1  | x3 ;
	t03 = x0  & x2 ;
	t04 = x2  ^ t02;
	t05 = x0  | t04;
	t06 = t01 & t05;
	t07 = x3  | t03;
	t08 = x1  ^ t06;
	t09 = t07 ^ t06;
	t10 = t04 | t03;
	t11 = x3  & t08;
	y2  =     ~ t09;
	y1  = t10 ^ t11;
	t14 = x0  | y2 ;
	t15 = t06 ^ y1 ;
	y3  = t01 ^ t04;
	t17 = x2  ^ t15;
	y0  = t14 ^ t17;

   y0 ^=  K[25*4+0];  y1 ^=  K[25*4+1];   y2 ^=  K[25*4+2];  y3 ^=  K[25*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */

	t01 = x2  ^ x3 ;
	t02 = x0  | x1 ;
	t03 = x1  | x2 ;
	t04 = x2  & t01;
	t05 = t02 ^ t01;
	t06 = x0  | t04;
	y2  =     ~ t05;
	t08 = x1  ^ x3 ;
	t09 = t03 & t08;
	t10 = x3  | y2 ;
	y1  = t09 ^ t06;
	t12 = x0  | t05;
	t13 = y1  ^ t12;
	t14 = t03 ^ t10;
	t15 = x0  ^ x2 ;
	y3  = t14 ^ t13;
	t17 = t05 & t13;
	t18 = t14 | t17;
	y0  = t15 ^ t18;

   y0 ^=  K[24*4+0];  y1 ^=  K[24*4+1];   y2 ^=  K[24*4+2];  y3 ^=  K[24*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */

	t01 = x0  & x1 ;
	t02 = x0  | x1 ;
	t03 = x2  | t01;
	t04 = x3  & t02;
	y3  = t03 ^ t04;
	t06 = x1  ^ t04;
	t07 = x3  ^ y3 ;
	t08 =     ~ t07;
	t09 = t06 | t08;
	t10 = x1  ^ x3 ;
	t11 = x0  | x3 ;
	y1  = x0  ^ t09;
	t13 = x2  ^ t06;
	t14 = x2  & t11;
	t15 = x3  | y1 ;
	t16 = t01 | t10;
	y0  = t13 ^ t15;
	y2  = t14 ^ t16;

   y0 ^=  K[23*4+0];  y1 ^=  K[23*4+1];   y2 ^=  K[23*4+2];  y3 ^=  K[23*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */

	t01 = x0  ^ x2 ;
	t02 =     ~ x2 ;
	t03 = x1  & t01;
	t04 = x1  | t02;
	t05 = x3  | t03;
	t06 = x1  ^ x3 ;
	t07 = x0  & t04;
	t08 = x0  | t02;
	t09 = t07 ^ t05;
	y1  = t06 ^ t08;
	y0  =     ~ t09;
	t12 = x1  & y0 ;
	t13 = t01 & t05;
	t14 = t01 ^ t12;
	t15 = t07 ^ t13;
	t16 = x3  | t02;
	t17 = x0  ^ y1 ;
	y3  = t17 ^ t15;
	y2  = t16 ^ t14;

   y0 ^=  K[22*4+0];  y1 ^=  K[22*4+1];   y2 ^=  K[22*4+2];  y3 ^=  K[22*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */

	t01 = x0  & x3 ;
	t02 = x2  ^ t01;
	t03 = x0  ^ x3 ;
	t04 = x1  & t02;
	t05 = x0  & x2 ;
	y0  = t03 ^ t04;
	t07 = x0  & y0 ;
	t08 = t01 ^ y0 ;
	t09 = x1  | t05;
	t10 =     ~ x1 ;
	y1  = t08 ^ t09;
	t12 = t10 | t07;
	t13 = y0  | y1 ;
	y3  = t02 ^ t12;
	t15 = t02 ^ t13;
	t16 = x1  ^ x3 ;
	y2  = t16 ^ t15;

   y0 ^=  K[21*4+0];  y1 ^=  K[21*4+1];   y2 ^=  K[21*4+2];  y3 ^=  K[21*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */

	t01 = x1  | x3 ;
	t02 = x2  | x3 ;
	t03 = x0  & t01;
	t04 = x1  ^ t02;
	t05 = x2  ^ x3 ;
	t06 =     ~ t03;
	t07 = x0  & t04;
	y1  = t05 ^ t07;
	t09 = y1  | t06;
	t10 = x0  ^ t07;
	t11 = t01 ^ t09;
	t12 = x3  ^ t04;
	t13 = x2  | t10;
	y3  = t03 ^ t12;
	t15 = x0  ^ t04;
	y2  = t11 ^ t13;
	y0  = t15 ^ t09;

   y0 ^=  K[20*4+0];  y1 ^=  K[20*4+1];   y2 ^=  K[20*4+2];  y3 ^=  K[20*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */

	t01 = x2  | x3 ;
	t02 = x0  | x3 ;
	t03 = x2  ^ t02;
	t04 = x1  ^ t02;
	t05 = x0  ^ x3 ;
	t06 = t04 & t03;
	t07 = x1  & t01;
	y2  = t05 ^ t06;
	t09 = x0  ^ t03;
	y0  = t07 ^ t03;
	t11 = y0  | t05;
	t12 = t09 & t11;
	t13 = x0  & y2 ;
	t14 = t01 ^ t05;
	y1  = x1  ^ t12;
	t16 = x1  | t13;
	y3  = t14 ^ t16;

   y0 ^=  K[19*4+0];  y1 ^=  K[19*4+1];   y2 ^=  K[19*4+2];  y3 ^=  K[19*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */

	t01 = x0  ^ x3 ;
	t02 = x2  ^ x3 ;
	t03 = x0  & x2 ;
	t04 = x1  | t02;
	y0  = t01 ^ t04;
	t06 = x0  | x2 ;
	t07 = x3  | y0 ;
	t08 =     ~ x3 ;
	t09 = x1  & t06;
	t10 = t08 | t03;
	t11 = x1  & t07;
	t12 = t06 & t02;
	y3  = t09 ^ t10;
	y1  = t12 ^ t11;
	t15 = x2  & y3 ;
	t16 = y0  ^ y1 ;
	t17 = t10 ^ t15;
	y2  = t16 ^ t17;

   y0 ^=  K[18*4+0];  y1 ^=  K[18*4+1];   y2 ^=  K[18*4+2];  y3 ^=  K[18*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */

	t01 = x0  ^ x1 ;
	t02 = x1  | x3 ;
	t03 = x0  & x2 ;
	t04 = x2  ^ t02;
	t05 = x0  | t04;
	t06 = t01 & t05;
	t07 = x3  | t03;
	t08 = x1  ^ t06;
	t09 = t07 ^ t06;
	t10 = t04 | t03;
	t11 = x3  & t08;
	y2  =     ~ t09;
	y1  = t10 ^ t11;
	t14 = x0  | y2 ;
	t15 = t06 ^ y1 ;
	y3  = t01 ^ t04;
	t17 = x2  ^ t15;
	y0  = t14 ^ t17;

   y0 ^=  K[17*4+0];  y1 ^=  K[17*4+1];   y2 ^=  K[17*4+2];  y3 ^=  K[17*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */

	t01 = x2  ^ x3 ;
	t02 = x0  | x1 ;
	t03 = x1  | x2 ;
	t04 = x2  & t01;
	t05 = t02 ^ t01;
	t06 = x0  | t04;
	y2  =     ~ t05;
	t08 = x1  ^ x3 ;
	t09 = t03 & t08;
	t10 = x3  | y2 ;
	y1  = t09 ^ t06;
	t12 = x0  | t05;
	t13 = y1  ^ t12;
	t14 = t03 ^ t10;
	t15 = x0  ^ x2 ;
	y3  = t14 ^ t13;
	t17 = t05 & t13;
	t18 = t14 | t17;
	y0  = t15 ^ t18;

   y0 ^=  K[16*4+0];  y1 ^=  K[16*4+1];   y2 ^=  K[16*4+2];  y3 ^=  K[16*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */

	t01 = x0  & x1 ;
	t02 = x0  | x1 ;
	t03 = x2  | t01;
	t04 = x3  & t02;
	y3  = t03 ^ t04;
	t06 = x1  ^ t04;
	t07 = x3  ^ y3 ;
	t08 =     ~ t07;
	t09 = t06 | t08;
	t10 = x1  ^ x3 ;
	t11 = x0  | x3 ;
	y1  = x0  ^ t09;
	t13 = x2  ^ t06;
	t14 = x2  & t11;
	t15 = x3  | y1 ;
	t16 = t01 | t10;
	y0  = t13 ^ t15;
	y2  = t14 ^ t16;

   y0 ^=  K[15*4+0];  y1 ^=  K[15*4+1];   y2 ^=  K[15*4+2];  y3 ^=  K[15*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */

	t01 = x0  ^ x2 ;
	t02 =     ~ x2 ;
	t03 = x1  & t01;
	t04 = x1  | t02;
	t05 = x3  | t03;
	t06 = x1  ^ x3 ;
	t07 = x0  & t04;
	t08 = x0  | t02;
	t09 = t07 ^ t05;
	y1  = t06 ^ t08;
	y0  =     ~ t09;
	t12 = x1  & y0 ;
	t13 = t01 & t05;
	t14 = t01 ^ t12;
	t15 = t07 ^ t13;
	t16 = x3  | t02;
	t17 = x0  ^ y1 ;
	y3  = t17 ^ t15;
	y2  = t16 ^ t14;

   y0 ^=  K[14*4+0];  y1 ^=  K[14*4+1];   y2 ^=  K[14*4+2];  y3 ^=  K[14*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */

	t01 = x0  & x3 ;
	t02 = x2  ^ t01;
	t03 = x0  ^ x3 ;
	t04 = x1  & t02;
	t05 = x0  & x2 ;
	y0  = t03 ^ t04;
	t07 = x0  & y0 ;
	t08 = t01 ^ y0 ;
	t09 = x1  | t05;
	t10 =     ~ x1 ;
	y1  = t08 ^ t09;
	t12 = t10 | t07;
	t13 = y0  | y1 ;
	y3  = t02 ^ t12;
	t15 = t02 ^ t13;
	t16 = x1  ^ x3 ;
	y2  = t16 ^ t15;

   y0 ^=  K[13*4+0];  y1 ^=  K[13*4+1];   y2 ^=  K[13*4+2];  y3 ^=  K[13*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */

	t01 = x1  | x3 ;
	t02 = x2  | x3 ;
	t03 = x0  & t01;
	t04 = x1  ^ t02;
	t05 = x2  ^ x3 ;
	t06 =     ~ t03;
	t07 = x0  & t04;
	y1  = t05 ^ t07;
	t09 = y1  | t06;
	t10 = x0  ^ t07;
	t11 = t01 ^ t09;
	t12 = x3  ^ t04;
	t13 = x2  | t10;
	y3  = t03 ^ t12;
	t15 = x0  ^ t04;
	y2  = t11 ^ t13;
	y0  = t15 ^ t09;

   y0 ^=  K[12*4+0];  y1 ^=  K[12*4+1];   y2 ^=  K[12*4+2];  y3 ^=  K[12*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */

	t01 = x2  | x3 ;
	t02 = x0  | x3 ;
	t03 = x2  ^ t02;
	t04 = x1  ^ t02;
	t05 = x0  ^ x3 ;
	t06 = t04 & t03;
	t07 = x1  & t01;
	y2  = t05 ^ t06;
	t09 = x0  ^ t03;
	y0  = t07 ^ t03;
	t11 = y0  | t05;
	t12 = t09 & t11;
	t13 = x0  & y2 ;
	t14 = t01 ^ t05;
	y1  = x1  ^ t12;
	t16 = x1  | t13;
	y3  = t14 ^ t16;

   y0 ^=  K[11*4+0];  y1 ^=  K[11*4+1];   y2 ^=  K[11*4+2];  y3 ^=  K[11*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */

	t01 = x0  ^ x3 ;
	t02 = x2  ^ x3 ;
	t03 = x0  & x2 ;
	t04 = x1  | t02;
	y0  = t01 ^ t04;
	t06 = x0  | x2 ;
	t07 = x3  | y0 ;
	t08 =     ~ x3 ;
	t09 = x1  & t06;
	t10 = t08 | t03;
	t11 = x1  & t07;
	t12 = t06 & t02;
	y3  = t09 ^ t10;
	y1  = t12 ^ t11;
	t15 = x2  & y3 ;
	t16 = y0  ^ y1 ;
	t17 = t10 ^ t15;
	y2  = t16 ^ t17;

   y0 ^=  K[10*4+0];  y1 ^=  K[10*4+1];   y2 ^=  K[10*4+2];  y3 ^=  K[10*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */

	t01 = x0  ^ x1 ;
	t02 = x1  | x3 ;
	t03 = x0  & x2 ;
	t04 = x2  ^ t02;
	t05 = x0  | t04;
	t06 = t01 & t05;
	t07 = x3  | t03;
	t08 = x1  ^ t06;
	t09 = t07 ^ t06;
	t10 = t04 | t03;
	t11 = x3  & t08;
	y2  =     ~ t09;
	y1  = t10 ^ t11;
	t14 = x0  | y2 ;
	t15 = t06 ^ y1 ;
	y3  = t01 ^ t04;
	t17 = x2  ^ t15;
	y0  = t14 ^ t17;

   y0 ^=  K[ 9*4+0];  y1 ^=  K[ 9*4+1];   y2 ^=  K[ 9*4+2];  y3 ^=  K[ 9*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */

	t01 = x2  ^ x3 ;
	t02 = x0  | x1 ;
	t03 = x1  | x2 ;
	t04 = x2  & t01;
	t05 = t02 ^ t01;
	t06 = x0  | t04;
	y2  =     ~ t05;
	t08 = x1  ^ x3 ;
	t09 = t03 & t08;
	t10 = x3  | y2 ;
	y1  = t09 ^ t06;
	t12 = x0  | t05;
	t13 = y1  ^ t12;
	t14 = t03 ^ t10;
	t15 = x0  ^ x2 ;
	y3  = t14 ^ t13;
	t17 = t05 & t13;
	t18 = t14 | t17;
	y0  = t15 ^ t18;

   y0 ^=  K[ 8*4+0];  y1 ^=  K[ 8*4+1];   y2 ^=  K[ 8*4+2];  y3 ^=  K[ 8*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 */

/* depth = 9,7,3,3, Total gates=18 */

	t01 = x0  & x1 ;
	t02 = x0  | x1 ;
	t03 = x2  | t01;
	t04 = x3  & t02;
	y3  = t03 ^ t04;
	t06 = x1  ^ t04;
	t07 = x3  ^ y3 ;
	t08 =     ~ t07;
	t09 = t06 | t08;
	t10 = x1  ^ x3 ;
	t11 = x0  | x3 ;
	y1  = x0  ^ t09;
	t13 = x2  ^ t06;
	t14 = x2  & t11;
	t15 = x3  | y1 ;
	t16 = t01 | t10;
	y0  = t13 ^ t15;
	y2  = t14 ^ t16;

   y0 ^=  K[ 7*4+0];  y1 ^=  K[ 7*4+1];   y2 ^=  K[ 7*4+2];  y3 ^=  K[ 7*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 */

/* depth = 5,3,8,6, Total gates=19 */

	t01 = x0  ^ x2 ;
	t02 =     ~ x2 ;
	t03 = x1  & t01;
	t04 = x1  | t02;
	t05 = x3  | t03;
	t06 = x1  ^ x3 ;
	t07 = x0  & t04;
	t08 = x0  | t02;
	t09 = t07 ^ t05;
	y1  = t06 ^ t08;
	y0  =     ~ t09;
	t12 = x1  & y0 ;
	t13 = t01 & t05;
	t14 = t01 ^ t12;
	t15 = t07 ^ t13;
	t16 = x3  | t02;
	t17 = x0  ^ y1 ;
	y3  = t17 ^ t15;
	y2  = t16 ^ t14;

   y0 ^=  K[ 6*4+0];  y1 ^=  K[ 6*4+1];   y2 ^=  K[ 6*4+2];  y3 ^=  K[ 6*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 */

/* depth = 4,6,9,7, Total gates=17 */

	t01 = x0  & x3 ;
	t02 = x2  ^ t01;
	t03 = x0  ^ x3 ;
	t04 = x1  & t02;
	t05 = x0  & x2 ;
	y0  = t03 ^ t04;
	t07 = x0  & y0 ;
	t08 = t01 ^ y0 ;
	t09 = x1  | t05;
	t10 =     ~ x1 ;
	y1  = t08 ^ t09;
	t12 = t10 | t07;
	t13 = y0  | y1 ;
	y3  = t02 ^ t12;
	t15 = t02 ^ t13;
	t16 = x1  ^ x3 ;
	y2  = t16 ^ t15;

   y0 ^=  K[ 5*4+0];  y1 ^=  K[ 5*4+1];   y2 ^=  K[ 5*4+2];  y3 ^=  K[ 5*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 */

/* depth = 6,4,7,3, Total gates=17 */

	t01 = x1  | x3 ;
	t02 = x2  | x3 ;
	t03 = x0  & t01;
	t04 = x1  ^ t02;
	t05 = x2  ^ x3 ;
	t06 =     ~ t03;
	t07 = x0  & t04;
	y1  = t05 ^ t07;
	t09 = y1  | t06;
	t10 = x0  ^ t07;
	t11 = t01 ^ t09;
	t12 = x3  ^ t04;
	t13 = x2  | t10;
	y3  = t03 ^ t12;
	t15 = x0  ^ t04;
	y2  = t11 ^ t13;
	y0  = t15 ^ t09;

   y0 ^=  K[ 4*4+0];  y1 ^=  K[ 4*4+1];   y2 ^=  K[ 4*4+2];  y3 ^=  K[ 4*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 */

/* depth = 3,6,4,4, Total gates=17 */

	t01 = x2  | x3 ;
	t02 = x0  | x3 ;
	t03 = x2  ^ t02;
	t04 = x1  ^ t02;
	t05 = x0  ^ x3 ;
	t06 = t04 & t03;
	t07 = x1  & t01;
	y2  = t05 ^ t06;
	t09 = x0  ^ t03;
	y0  = t07 ^ t03;
	t11 = y0  | t05;
	t12 = t09 & t11;
	t13 = x0  & y2 ;
	t14 = t01 ^ t05;
	y1  = x1  ^ t12;
	t16 = x1  | t13;
	y3  = t14 ^ t16;

   y0 ^=  K[ 3*4+0];  y1 ^=  K[ 3*4+1];   y2 ^=  K[ 3*4+2];  y3 ^=  K[ 3*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 */

/* depth = 3,6,8,3, Total gates=18 */

	t01 = x0  ^ x3 ;
	t02 = x2  ^ x3 ;
	t03 = x0  & x2 ;
	t04 = x1  | t02;
	y0  = t01 ^ t04;
	t06 = x0  | x2 ;
	t07 = x3  | y0 ;
	t08 =     ~ x3 ;
	t09 = x1  & t06;
	t10 = t08 | t03;
	t11 = x1  & t07;
	t12 = t06 & t02;
	y3  = t09 ^ t10;
	y1  = t12 ^ t11;
	t15 = x2  & y3 ;
	t16 = y0  ^ y1 ;
	t17 = t10 ^ t15;
	y2  = t16 ^ t17;

   y0 ^=  K[ 2*4+0];  y1 ^=  K[ 2*4+1];   y2 ^=  K[ 2*4+2];  y3 ^=  K[ 2*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 */

/* depth = 7,4,5,3, Total gates=18 */

	t01 = x0  ^ x1 ;
	t02 = x1  | x3 ;
	t03 = x0  & x2 ;
	t04 = x2  ^ t02;
	t05 = x0  | t04;
	t06 = t01 & t05;
	t07 = x3  | t03;
	t08 = x1  ^ t06;
	t09 = t07 ^ t06;
	t10 = t04 | t03;
	t11 = x3  & t08;
	y2  =     ~ t09;
	y1  = t10 ^ t11;
	t14 = x0  | y2 ;
	t15 = t06 ^ y1 ;
	y3  = t01 ^ t04;
	t17 = x2  ^ t15;
	y0  = t14 ^ t17;

   y0 ^=  K[ 1*4+0];  y1 ^=  K[ 1*4+1];   y2 ^=  K[ 1*4+2];  y3 ^=  K[ 1*4+3] ;
    x2  = ((((   y2  ))<<(32-(  22 )))| (int)((uint)((   y2  ))>>(  22 ))) ;   x0  = ((((  y0  ))<<(32-(  5 )))| (int)((uint)((  y0  ))>>(  5 ))) ;   x2  =   x2  ^   y3  ^ (  y1 <<7);   x0  =   x0  ^   y1  ^   y3 ;   x3  = ((((   y3  ))<<(32-(  7 )))| (int)((uint)((   y3  ))>>(  7 ))) ;   x1  = ((((   y1  ))<<(32-(  1 )))| (int)((uint)((   y1  ))>>(  1 ))) ;   x3  =   x3  ^   x2  ^ (  x0 )<<3;   x1  =   x1  ^   x0  ^   x2 ;   x2  = ((((   x2  ))<<(32-(  3 )))| (int)((uint)((   x2  ))>>(  3 ))) ;   x0  = ((((   x0  ))<<(32-(  13 )))| (int)((uint)((   x0  ))>>(  13 )))  ;

/* InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 */

/* depth = 8,4,3,6, Total gates=19 */

	t01 = x2  ^ x3 ;
	t02 = x0  | x1 ;
	t03 = x1  | x2 ;
	t04 = x2  & t01;
	t05 = t02 ^ t01;
	t06 = x0  | t04;
	y2  =     ~ t05;
	t08 = x1  ^ x3 ;
	t09 = t03 & t08;
	t10 = x3  | y2 ;
	y1  = t09 ^ t06;
	t12 = x0  | t05;
	t13 = y1  ^ t12;
	t14 = t03 ^ t10;
	t15 = x0  ^ x2 ;
	y3  = t14 ^ t13;
	t17 = t05 & t13;
	t18 = t14 | t17;
	y0  = t15 ^ t18;

  x0 = y0; x1 = y1; x2 = y2; x3 = y3;
   x0 ^=  K[ 0*4+0];  x1 ^=  K[ 0*4+1];   x2 ^=  K[ 0*4+2];  x3 ^=  K[ 0*4+3] ;


        byte[] result = new byte[] {
            (byte)(x0), (byte)((uint)x0 >> 8), (byte)((uint)x0 >> 16), (byte)((uint)x0 >> 24),
            (byte)(x1), (byte)((uint)x1 >> 8), (byte)((uint)x1 >> 16), (byte)((uint)x1 >> 24),
            (byte)(x2), (byte)((uint)x2 >> 8), (byte)((uint)x2 >> 16), (byte)((uint)x2 >> 24),
            (byte)(x3), (byte)((uint)x3 >> 8), (byte)((uint)x3 >> 16), (byte)((uint)x3 >> 24)
        };
if (DEBUG && debuglevel > 6) {
Console.WriteLine("PT="+toString(result));
Console.WriteLine();
}
if (DEBUG) trace(OUT, "blockDecrypt()");
        return result;
    }


// utility static methods (from cryptix.util.core ArrayUtil and Hex classes)
//...........................................................................

    /**
     * Compares two byte arrays for equality.
     *
     * @return true if the arrays have identical contents
     */
    private static bool areEqual (byte[] a, byte[] b) {
        int aLength = a.Length;
        if (aLength != b.Length)
            return false;
        for (int i = 0; i < aLength; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }

    /**
     * Returns a string of 8 hexadecimal digits (most significant
     * digit first) corresponding to the integer <i>n</i>, which is
     * treated as unsigned.
     */
    public static String intToString (int n) {
        char[] buf = new char[8];
        for (int i = 7; i >= 0; i--) {
            buf[i] = HEX_DIGITS[n & 0x0F];
            n = (int)((uint)n >> 4);
        }
        return new String(buf);
    }

    /**
     * Returns a string of hexadecimal digits from a byte array. Each
     * byte is converted to 2 hex symbols.
     */
    private static String toString (byte[] ba) {
        int length = ba.Length;
        char[] buf = new char[length * 2];
        for (int i = 0, j = 0, k; i < length; ) {
            k = ba[i++];
            buf[j++] = HEX_DIGITS[((uint)k >> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k        & 0x0F];
        }
        return new String(buf);
    }

    /**
     * Returns a string of hexadecimal digits from an integer array. Each
     * int is converted to 4 hex symbols.
     */
    private static String toString (int[] ia) {
        int length = ia.Length;
        char[] buf = new char[length * 8];
        for (int i = 0, j = 0, k; i < length; i++) {
            k = ia[i];
            buf[j++] = HEX_DIGITS[((uint)k >> 28) & 0x0F];
            buf[j++] = HEX_DIGITS[((uint)k >> 24) & 0x0F];
            buf[j++] = HEX_DIGITS[((uint)k >> 20) & 0x0F];
            buf[j++] = HEX_DIGITS[((uint)k >> 16) & 0x0F];
            buf[j++] = HEX_DIGITS[((uint)k >> 12) & 0x0F];
            buf[j++] = HEX_DIGITS[((uint)k >>  8) & 0x0F];
            buf[j++] = HEX_DIGITS[((uint)k >> 4) & 0x0F];
            buf[j++] = HEX_DIGITS[ k         & 0x0F];
        }
        return new String(buf);
    }
}

}
