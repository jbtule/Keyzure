using System;
using System.IO;
using Keyczar;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;

namespace Keyzure.Keys
{
    public class VaultRsaPrivCrypt:VaultRsaBase,ICrypterKey
    {
        public VaultRsaPrivCrypt()
        {
        }

        public HashingStream GetAuthSigningStream(KeyczarBase keyczar)
        {
            throw new NotImplementedException();
        }

        public VerifyingStream GetAuthVerifyingStream(KeyczarBase keyczar)
        {
            throw new NotImplementedException();
        }

        public FinishingStream GetDecryptingStream(Stream output, KeyczarBase keyczar)
        {
            throw new NotImplementedException();
        }

        public FinishingStream GetEncryptingStream(Stream output, KeyczarBase keyczar)
        {
            throw new NotImplementedException();
        }
    }
}
