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
    public class CertCryptedKeySet : ILayeredKeySet
    {

        public static Func<IKeySet, CertCryptedKeySet> Creator(
            IKeySet keyset, Stream certStream, Func<string> passwordPrompt = null)
                => keySet => new CertCryptedKeySet(keyset, certStream, passwordPrompt);

        public static Func<IKeySet, CertCryptedKeySet> Creator(
            IKeySet keyset, string thumbPrint)
                => keySet => new CertCryptedKeySet(keyset, thumbPrint);
        private IKeySet _keySet;

        public CertCryptedKeySet(IKeySet keySet, Stream certStream, Func<string> passwordPrompt = null)
        {
            _keySet = keySet;
            _certKeySet = ImportedKeySet.Import.Pkcs12Keys(KeyPurpose.DecryptAndEncrypt, certStream, passwordPrompt);
            _crypter = new Crypter(_certKeySet);
            _sessionPacker = new BsonSessionKeyPacker();
        }

        public CertCryptedKeySet(IKeySet keySet, string thumbPrint)
        {
            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint,false);
            var cert = certCollection.OfType<X509Certificate2>().FirstOrDefault();
            var privKey = cert?.GetRSAPrivateKey();
            var keyParam = DotNetUtilities.GetRsaKeyPair(privKey).Private as RsaPrivateCrtKeyParameters;
            var key = new RsaPrivateKey()
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
                SessionMaterial = sessionMaterial.ToBytes();
                CipherText = cipherText;
            }

            public byte[] SessionMaterial { get; set; }

            public byte[] CipherText { get; set; }
        }


        public KeyMetadata Metadata => throw new NotImplementedException();

        public byte[] GetKeyData(int version)
        {
            SessionPack pack;
            var data = _keySet.GetKeyData(version);
            using (var ms = new MemoryStream(data))
            using (BsonReader reader = new BsonReader(ms))
            {
                var jsonSerializer =
                    JsonSerializer.Create(new JsonSerializerSettings
                    {
                        ContractResolver =new CamelCasePropertyNamesContractResolver()
                    });
                pack = jsonSerializer.Deserialize<SessionPack>(reader);

            }

            using (var sessionCrypter = new SessionCrypter(_crypter, WebBase64.FromBytes(pack.SessionMaterial),keyPacker:_sessionPacker))
            {
                return sessionCrypter.Decrypt(pack.CipherText);
            }
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls
        private ImportedKeySet _certKeySet;
        private Crypter _crypter;
        private BsonSessionKeyPacker _sessionPacker;

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
