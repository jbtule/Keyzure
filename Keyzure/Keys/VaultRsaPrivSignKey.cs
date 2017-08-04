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

        public HashingStream GetSigningStream(Keyczar.Keyczar keyczar)
        {
            throw new NotImplementedException();
        }

        public VerifyingStream GetVerifyingStream(Keyczar.Keyczar keyczar)
        {
            throw new NotImplementedException();
        }
    }
}
