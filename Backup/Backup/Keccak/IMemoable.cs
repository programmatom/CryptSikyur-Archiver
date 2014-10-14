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

namespace Org.BouncyCastle.Utilities
{
	public interface IMemoable
	{
		/// <summary>
		/// Produce a copy of this object with its configuration and in its current state.
		/// </summary>
		/// <remarks>
		/// The returned object may be used simply to store the state, or may be used as a similar object
		/// starting from the copied state.
		/// </remarks>
		IMemoable Copy();

		/// <summary>
		/// Restore a copied object state into this object.
		/// </summary>
		/// <remarks>
		/// Implementations of this method <em>should</em> try to avoid or minimise memory allocation to perform the reset.
		/// </remarks>
		/// <param name="other">an object originally {@link #copy() copied} from an object of the same type as this instance.</param>
		/// <exception cref="InvalidCastException">if the provided object is not of the correct type.</exception>
		/// <exception cref="MemoableResetException">if the <b>other</b> parameter is in some other way invalid.</exception>
		void Reset(IMemoable other);
	}

}

