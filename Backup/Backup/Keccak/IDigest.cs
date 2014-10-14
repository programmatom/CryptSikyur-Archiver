// This file taken from BouncyCastle C# library:
// http://www.bouncycastle.org/csharp/
// File is left as unchanged as possible - only unused code has been disabled with preprocessor directives
//
// BouncyCastle C# is licensed under a derivative of the MIT X11 license
// MIT X11 license: http://opensource.org/licenses/mit-license.php
// BouncyCastle license: http://www.bouncycastle.org/csharp/licence.html
// GNU opinion: http://www.gnu.org/licenses/license-list.html#X11License
// In GNU's opinion, MIT X11 is compatible with GPL.
//
// BouncyCastle License:
//
// Copyright (c) 2000 - 2011 The Legion of the Bouncy Castle Inc. (http://www.bouncycastle.org)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included in all copies or substantial
// portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. 
using System;

namespace Org.BouncyCastle.Crypto
{
    /**
     * interface that a message digest conforms to.
     */
    public interface IDigest
    {
        /**
         * return the algorithm name
         *
         * @return the algorithm name
         */
        string AlgorithmName { get; }

		/**
         * return the size, in bytes, of the digest produced by this message digest.
         *
         * @return the size, in bytes, of the digest produced by this message digest.
         */
		int GetDigestSize();

		/**
         * return the size, in bytes, of the internal buffer used by this digest.
         *
         * @return the size, in bytes, of the internal buffer used by this digest.
         */
		int GetByteLength();

		/**
         * update the message digest with a single byte.
         *
         * @param inByte the input byte to be entered.
         */
        void Update(byte input);

        /**
         * update the message digest with a block of bytes.
         *
         * @param input the byte array containing the data.
         * @param inOff the offset into the byte array where the data starts.
         * @param len the length of the data.
         */
        void BlockUpdate(byte[] input, int inOff, int length);

        /**
         * Close the digest, producing the final digest value. The doFinal
         * call leaves the digest reset.
         *
         * @param output the array the digest is to be copied into.
         * @param outOff the offset into the out array the digest is to start at.
         */
        int DoFinal(byte[] output, int outOff);

        /**
         * reset the digest back to it's initial state.
         */
        void Reset();
    }
}
