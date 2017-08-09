using System;
using Keyczar;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http.Headers;
using Keyczar.Crypto;
using Keyzure.Utility;
using System.Collections.Generic;
using System.Globalization;
using Keyczar.Unofficial;

namespace Keyzure.Providers
{
    public class KeyzureCryptoProvider: ICryptoProvider

    {
        
        internal static readonly string RsaPssSha256 ="PS256";
        internal static readonly string RsaPssSha384 ="PS384";
        internal static readonly string RsaPssSha512 ="PS512";

        
        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {
                 
            var hashSet = new HashSet<string> {RsaPssSha256, RsaPssSha384, RsaPssSha512};
            
            if (args.Length != 2 || !hashSet.Contains(algorithm))
            {
                return false;
            }
            if (!(args[0] is KeySetKey key) || !(args[1] is bool shouldSign))
            {
                return false;
            }

            var isPrivate = key.KeySet.Metadata.Kind == KeyKind.Private;
            var isPublic = key.KeySet.Metadata.Kind == KeyKind.Public;
            var isSign = key.KeySet.Metadata.Purpose == KeyPurpose.SignAndVerify;
            var isVerify = key.KeySet.Metadata.Purpose == KeyPurpose.Verify;
                
            if (shouldSign && isPrivate && isSign)
            {
                return GetAlgorithmFromKeySet(key.KeySet) == algorithm;
            }
            else if(!shouldSign && (isPrivate || isPublic) && (isSign && isVerify))
            {
                return key.KeySet.Metadata.Versions.Select(it => key.KeySet.GetKey(it.VersionNumber))
                    .Any(it => GetAlgorithmFromKey(it) == algorithm);
            }

            return false;
        }

        public object Create(string algorithm, params object[] args)
        {
            if ((args[0] is KeySetKey key) && (args[1] is bool shouldSign))
            {
                
                return new KeyzureSignatureProvider(key, algorithm, shouldSign);
            }
            throw new InvalidKeyTypeException("Not a valid keyset, shouldn't have been called");
        }

        public void Release(object cryptoInstance)
        {
            (cryptoInstance as IDisposable)?.Dispose();
        }
        
        internal static string GetAlgorithmFromKey(Key key)
        {
            switch (key)
            {
                case Keyczar.Unofficial.RsaPrivateSignKey rsaKey
                when rsaKey.Digest == Keyczar.Unofficial.DigestAlg.Sha256:
                    return KeyzureCryptoProvider.RsaPssSha256;
                case Keyczar.Unofficial.RsaPrivateSignKey rsaKey
                when rsaKey.Digest == Keyczar.Unofficial.DigestAlg.Sha384:
                    return KeyzureCryptoProvider.RsaPssSha384;
                case Keyczar.Unofficial.RsaPrivateSignKey rsaKey
                when rsaKey.Digest == Keyczar.Unofficial.DigestAlg.Sha512:
                    return KeyzureCryptoProvider.RsaPssSha512;
                default:
                    return null;
            }
        }
        
        internal static string GetAlgorithmFromKeySet(IKeySet keySet)
        {
            var primaryKey = keySet.GetPrimaryKey();
            var alg = KeyzureCryptoProvider.GetAlgorithmFromKey(primaryKey);
            if (alg == null)
            {
                throw new InvalidKeyTypeException($"Primary key Is not a valid JWA != '{primaryKey?.KeyType}'");
            }
            return alg;
        }
    }
}