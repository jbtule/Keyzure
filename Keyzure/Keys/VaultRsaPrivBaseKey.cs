using System;
using Keyczar;

namespace Keyzure.Keys
{
    public class VaultRsaBase:Key
    {
        public VaultRsaBase()
        {
        }

        public override byte[] GetKeyHash()
        {
            throw new NotImplementedException();
        }

        protected override void GenerateKey(int size, KeyczarConfig config)
        {
            throw new NotImplementedException();
        }

        protected override void Dispose(bool disposing)
        {
            throw new NotImplementedException();
        }

    }
}
