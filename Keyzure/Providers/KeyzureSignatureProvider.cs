using System;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Unofficial;
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

            JwtAlg chosenAlg = Algorithm;

            if (!Jwt.IsValidAlg(chosenAlg, _keySet.GetPrimaryKey()))
            {
                throw new InvalidKeyTypeException("Key doesn't match chosen algorithm");
            }
            
            using (var vanillaSigner = new VanillaSigner(_keySet))
            {
                var sig = vanillaSigner.Sign(input);
                return sig;
            }
        }

        public override bool Verify(byte[] input, byte[] signature)
        {
            using (var vanillaVerifier = new VanillaVerifier(_keySet))
            {
                return vanillaVerifier.Verify(input,signature);
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