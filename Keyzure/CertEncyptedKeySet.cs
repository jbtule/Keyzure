using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Unofficial;
using Keyczar.Util;
using Newtonsoft.Json;
using Newtonsoft.Json.Bson;
using Newtonsoft.Json.Serialization;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Keyczar.Crypto;

namespace Keyzure
{
    public class CertEncryptedKeySet : ILayeredKeySet
    {
        private ImportedKeySet _certKeySet;
        private Crypter _crypter;
        private readonly BsonSessionKeyPacker _sessionPacker;

        public static Func<IKeySet, CertEncryptedKeySet> Creator(Stream certStream, Func<string> passwordPrompt = null)
                => keySet => new CertEncryptedKeySet(keySet, certStream, passwordPrompt);

        public static Func<IKeySet, CertEncryptedKeySet> Creator(string thumbPrint)
                => keySet => new CertEncryptedKeySet(keySet, thumbPrint);
        private IKeySet _keySet;

        public CertEncryptedKeySet(IKeySet keySet, Stream certStream, Func<string> passwordPrompt = null)
        {
            _keySet = keySet;
            _certKeySet = ImportedKeySet.Import.Pkcs12Keys(KeyPurpose.DecryptAndEncrypt, certStream, passwordPrompt);
            _crypter = new Crypter(_certKeySet);
            _sessionPacker = new BsonSessionKeyPacker();
        }

        internal static Key KeyFromBouncyCastle(RsaPrivateCrtKeyParameters keyParam)
        {
            return new RsaPrivateKey()
                   {
                       PublicKey = new RsaPublicKey()
                                   {
                                       Modulus = keyParam.Modulus.ToSystemBigInteger(),
                                       PublicExponent = keyParam.PublicExponent.ToSystemBigInteger(),
                                       Size = keyParam.Modulus.BitLength,
                                   },
                       PrimeP = keyParam.P.ToSystemBigInteger(),
                       PrimeExponentP = keyParam.DP.ToSystemBigInteger(),
                       PrimeExponentQ = keyParam.DQ.ToSystemBigInteger(),
                       PrimeQ = keyParam.Q.ToSystemBigInteger(),
                       CrtCoefficient = keyParam.QInv.ToSystemBigInteger(),
                       PrivateExponent = keyParam.Exponent.ToSystemBigInteger(),
                       Size = keyParam.Modulus.BitLength,
                   };
        }

        public CertEncryptedKeySet(IKeySet keySet, string thumbPrint)
        {
            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint,false);
            var cert = certCollection.OfType<X509Certificate2>().FirstOrDefault();
            var privKey = cert?.GetRSAPrivateKey();
            var keyParam = DotNetUtilities.GetRsaKeyPair(privKey).Private as RsaPrivateCrtKeyParameters;
            var key = KeyFromBouncyCastle(keyParam);

            _certKeySet = new ImportedKeySet(key, KeyPurpose.DecryptAndEncrypt, "imported from X509Store");

            _keySet = keySet;
            _crypter = new Crypter(_certKeySet);
            _sessionPacker = new BsonSessionKeyPacker();
        }


        public class SessionPack
        {
            public SessionPack()
            {
            }

            public SessionPack(WebBase64 sessionMaterial, byte[] cipherText)
            {
                Version = 1;

                SessionMaterial = sessionMaterial;
                CipherText = cipherText;
            }
            
            public int Version { get; set; }

            public WebBase64 SessionMaterial { get; set; }

            [JsonConverter(typeof (WebSafeBase64ByteConverter))]
            public byte[] CipherText { get; set; }
        }


        public KeyMetadata Metadata => _keySet.Metadata;

        public byte[] GetKeyData(int version)
        {
            var data = _keySet.GetKeyData(version);
            var jsonString = this.GetConfig().RawStringEncoding.GetString(data);
            var pack = JsonConvert.DeserializeObject<SessionPack>(jsonString);

          

            using (var sessionCrypter = new SessionCrypter(_crypter, pack.SessionMaterial,keyPacker:_sessionPacker))
            {
                return sessionCrypter.Decrypt(pack.CipherText);
            }
        }

        public KeyczarConfig Config { get; set; }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls
   

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _crypter =_crypter.SafeDispose();
                    _certKeySet = _certKeySet.SafeDispose();
                    _keySet = _keySet.SafeDispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~CertCryptedKeySet() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion


    }
}
