/*
 *  Copyright 2014 Thomas R. Lawrence
 *    except: "SkeinFish 0.5.0" sources, which is Copyright 2010 Alberto Fajardo
 *    except: "SerpentEngine.cs", which is Copyright © 1997, 1998 Systemics Ltd on behalf of the Cryptix Development Team
 * 
 *  GNU General Public License
 * 
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
*/
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Serpent
{
    // Basic serpent implementation for .NET: ICryptoTransform and SymmetricAlgorithm
    // Only ECB mode with no padding is supported (enough to support our use of CTR mode)

    public class SerpentTransform : ICryptoTransform
    {
        private static readonly int[] PermittedKeyLengthsBits = new int[] { 128, 192, 256 };
        private const int BlockLengthBytes = Serpent_BitSlice.BLOCK_SIZE;

        public enum Direction
        {
            Encrypt,
            Decrypt,
        }

        private Direction direction;
        private object engineKey;

        public SerpentTransform(Direction direction, byte[] key)
        {
            Debug.Assert((BlockLengthBytes & (BlockLengthBytes - 1)) == 0);

            if (Array.IndexOf(PermittedKeyLengthsBits, key.Length * 8) < 0)
            {
                throw new ArgumentException();
            }

            this.direction = direction;
            this.engineKey = Serpent_BitSlice.makeKey(key);
        }

        public bool CanReuseTransform { get { return false; } }
        public bool CanTransformMultipleBlocks { get { return true; } }
        public int InputBlockSize { get { return BlockLengthBytes; } }
        public int OutputBlockSize { get { return BlockLengthBytes; } }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if ((inputCount & (BlockLengthBytes - 1)) != 0)
            {
                throw new ArgumentException();
            }

            for (int i = 0; i < inputCount; i += BlockLengthBytes)
            {
                byte[] result;
                if (direction == Direction.Encrypt)
                {
                    result = Serpent_BitSlice.blockEncrypt(inputBuffer, inputOffset + i, engineKey);
                }
                else
                {
                    result = Serpent_BitSlice.blockDecrypt(inputBuffer, inputOffset + i, engineKey);
                }
                Debug.Assert(result.Length == BlockLengthBytes);
                Buffer.BlockCopy(result, 0, outputBuffer, outputOffset + i, BlockLengthBytes);
            }

            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] result = new byte[inputCount];
            Buffer.BlockCopy(inputBuffer, inputOffset, result, 0, inputCount);
            TransformBlock(result, 0, inputCount, result, 0);
            return result;
        }

        public void Dispose()
        {
            engineKey = null;
        }
    }


    public class SerpentAlgorithm : SymmetricAlgorithm
    {
        public SerpentAlgorithm()
        {
            base.BlockSizeValue = 128;
            base.FeedbackSizeValue = 0;
            base.IVValue = new byte[base.BlockSizeValue / 8];
            base.KeySizeValue = base.BlockSizeValue; // default, any of {128, 192, 256} are permitted
            base.KeyValue = new byte[base.KeySizeValue / 8];
            base.LegalBlockSizesValue = new KeySizes[] { new KeySizes(base.BlockSizeValue, base.BlockSizeValue, 0) };
            base.LegalKeySizesValue = new KeySizes[] { new KeySizes(128/*min*/, 256/*max*/, 64/*skip*/) };
            base.ModeValue = CipherMode.ECB;
            base.PaddingValue = PaddingMode.None;
        }

        public override CipherMode Mode
        {
            get
            {
                return base.Mode;
            }
            set
            {
                if (value != CipherMode.ECB)
                {
                    throw new NotSupportedException();
                }
                base.Mode = value;
            }
        }

        public override PaddingMode Padding
        {
            get
            {
                return base.Padding;
            }
            set
            {
                if (value != PaddingMode.None)
                {
                    throw new NotSupportedException();
                }
                base.Padding = value;
            }
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            // rgbIV is not used in ECB, but SymmetricAlgorithm insists on sending it anyway
            return new SerpentTransform(SerpentTransform.Direction.Decrypt, rgbKey);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            // rgbIV is not used in ECB, but SymmetricAlgorithm insists on sending it anyway
            return new SerpentTransform(SerpentTransform.Direction.Encrypt, rgbKey);
        }

        public override void GenerateIV()
        {
            throw new NotImplementedException();
        }

        public override void GenerateKey()
        {
            throw new NotImplementedException();
        }
    }
}
