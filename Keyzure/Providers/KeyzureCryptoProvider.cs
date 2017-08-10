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
        
        internal static readonly string HmacSha256 ="HS256";
        internal static readonly string HmacSha384 ="HS384";
        internal static readonly string HmacSha512 ="HS512";

        
        
        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {
                 
            var asymmHashSet = new HashSet<string>
            {
                RsaPssSha256, 
                RsaPssSha384,
                RsaPssSha512,
                
            };

            var symmSignSet = new HashSet<string>()
            {
                HmacSha256,
                HmacSha384,
                HmacSha512
            };
            
            if (args.Length != 2 || (!asymmHashSet.Contains(algorithm) && !symmSignSet.Contains(algorithm)))
            {
                return false;
            }
            if (!(args[0] is KeySetKey key) || !(args[1] is bool shouldSign))
            {
                return false;
            }
            
            var isSymm = key.KeySet.Metadata.Kind == KeyKind.Symmetric;
            var isPrivate = key.KeySet.Metadata.Kind == KeyKind.Private;
            var isPublic = key.KeySet.Metadata.Kind == KeyKind.Public;
            var isSign = key.KeySet.Metadata.Purpose == KeyPurpose.SignAndVerify;
            var isVerify = key.KeySet.Metadata.Purpose == KeyPurpose.Verify;

            if (!isSign && !isVerify)
            {
                return false; //Right now only support signing algorithms
            }
            
            
            if (isSymm && !symmSignSet.Contains(algorithm))
            {
                return false;
            }
            
            if (!isSymm && !asymmHashSet.Contains(algorithm))
            {
                return false;
            }
            
            // ReSharper disable once ConditionIsAlwaysTrueOrFalse  -- code may have other options in future
            if (isSymm && (isSign || isVerify))
            {
                return GetAlgorithmFromKeySet(key.KeySet) == algorithm;
            }else if (shouldSign && isPrivate && isSign)
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
                case Keyczar.Unofficial.HmacSha2Key hmacKey
                when hmacKey.Digest == Keyczar.Unofficial.DigestAlg.Sha256:
                    return KeyzureCryptoProvider.HmacSha256;
                case Keyczar.Unofficial.HmacSha2Key hmacKey
                when hmacKey.Digest == Keyczar.Unofficial.DigestAlg.Sha384:
                    return KeyzureCryptoProvider.HmacSha384;
                case Keyczar.Unofficial.HmacSha2Key hmacKey
                when hmacKey.Digest == Keyczar.Unofficial.DigestAlg.Sha512:
                    return KeyzureCryptoProvider.HmacSha512;
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