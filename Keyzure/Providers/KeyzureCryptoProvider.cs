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
        

        
        
        public bool IsSupportedAlgorithm(string algorithm, params object[] args)
        {

            JwtAlg intendedAlg = algorithm;
            
            //currently only support signing, these are the expected args
            if (args.Length != 2 || !(args[0] is KeySetKey key) || !(args[1] is bool shouldSign))
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
            
            // ReSharper disable once ConditionIsAlwaysTrueOrFalse  -- code may have other options in future
            if (isSymm && (isSign || isVerify))
            {
                return Jwt.IsValidAlg(intendedAlg, key.KeySet.GetPrimaryKey());
            }else if (shouldSign && isPrivate && isSign)
            {
                return  Jwt.IsValidAlg(intendedAlg, key.KeySet.GetPrimaryKey());
            }
            else if(!shouldSign && (isPrivate || isPublic) && (isSign && isVerify))
            {
                return key.KeySet.Metadata.Versions.Select(it => key.KeySet.GetKey(it.VersionNumber))
                    .Any(it => Jwt.AlgForKey(it) == intendedAlg);
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
        
    }
}