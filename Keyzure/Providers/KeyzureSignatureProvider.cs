using System;
using Keyczar;
using Keyczar.Compat;
using Microsoft.IdentityModel.Tokens;

namespace Keyzure.Providers
{
    public class KeyzureSignatureProvider: SignatureProvider
    {
        private readonly bool _signing;
        private IKeySet _keySet;

        public KeyzureSignatureProvider(KeySetKey key, string algorithm, bool signing) : base(key, algorithm)
        {
            _keySet = key.KeySet;
            _signing = signing;
        }

        public override byte[] Sign(byte[] input)
        {
            if (!_signing)
            {
                throw new InvalidOperationException();
            }
            using (var vanillaSigner = new VanillaSigner(_keySet))
            {
                return vanillaSigner.Sign(input);
            }
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            using (var vanillaSigner = new VanillaVerifier(_keySet))
            {
                return vanillaSigner.Verify(input,signature);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _keySet = null;
            }
        }
    }
}