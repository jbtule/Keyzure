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

        public HashingStream GetAuthSigningStream(Keyczar.Keyczar keyczar)
        {
            throw new NotImplementedException();
        }

        public VerifyingStream GetAuthVerifyingStream(Keyczar.Keyczar keyczar)
        {
            throw new NotImplementedException();
        }

        public FinishingStream GetDecryptingStream(Stream output, Keyczar.Keyczar keyczar)
        {
            throw new NotImplementedException();
        }

        public FinishingStream GetEncryptingStream(Stream output, Keyczar.Keyczar keyczar)
        {
            throw new NotImplementedException();
        }
    }
}
