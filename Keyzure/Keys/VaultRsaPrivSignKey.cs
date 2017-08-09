using System;
using Keyczar;
using Keyczar.Crypto;
using Keyczar.Crypto.Streams;

namespace Keyzure.Keys
{
    public class VaultRsaPrivSign:VaultRsaBase,ISignerKey
    {
        public VaultRsaPrivSign()
        {
        }

        public HashingStream GetSigningStream(KeyczarBase keyczar)
        {
            throw new NotImplementedException();
        }

        public VerifyingStream GetVerifyingStream(KeyczarBase keyczar)
        {
            throw new NotImplementedException();
        }
    }
}
