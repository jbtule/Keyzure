using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Keyczar;
using Keyczar.Compat;
using Keyczar.Unofficial;
using Keyczar.Util;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Keyzure
{
    public class CertEncryptedKeySetWriter : ILayeredKeySetWriter
    {
        private ImportedKeySet _certKeySet;
        private Encrypter _encrypter;
        private readonly BsonSessionKeyPacker _sessionPacker;


        public static Func<IKeySetWriter, CertEncryptedKeySetWriter> Creator(Stream certStream, Func<string> passwordPrompt = null)
            => writer => new CertEncryptedKeySetWriter(writer, certStream, passwordPrompt);

        public static Func<IKeySetWriter, CertEncryptedKeySetWriter> Creator(string thumbPrint)
            => writer => new CertEncryptedKeySetWriter(writer, thumbPrint);

        private IKeySetWriter _writer;

        public CertEncryptedKeySetWriter(IKeySetWriter writer, Stream certStream, Func<string> passwordPrompt = null)
        {
            _writer = writer;
            _certKeySet = ImportedKeySet.Import.Pkcs12Keys(KeyPurpose.DecryptAndEncrypt, certStream, passwordPrompt);
            _encrypter = new Crypter(_certKeySet);
            _sessionPacker = new BsonSessionKeyPacker();
        }

        public CertEncryptedKeySetWriter(IKeySetWriter writer, string thumbPrint)
        {
            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint, false);
            var cert = certCollection.OfType<X509Certificate2>().FirstOrDefault();
            var privKey = cert?.GetRSAPrivateKey();
            var keyParam = DotNetUtilities.GetRsaKeyPair(privKey).Private as RsaPrivateCrtKeyParameters;
            var key = CertEncryptedKeySet.KeyFromBouncyCastle(keyParam);

            _certKeySet = new ImportedKeySet(key, KeyPurpose.DecryptAndEncrypt, "imported from X509Store");

            _writer = writer;
            _encrypter = new Encrypter(_certKeySet);
            _sessionPacker = new BsonSessionKeyPacker();

        }


        public bool Finish()
        {
            return _writer.Finish();
        }

        public KeyczarConfig Config { get; set; }

        public void Write(byte[] keyData, int version)
        {

            using (var sessionCrypter = new SessionCrypter(_encrypter, keySize: 256,
                symmetricKeyType: UnofficialKeyType.AesAead, keyPacker: _sessionPacker))
            {
                var sessionMaterial = sessionCrypter.SessionMaterial;
                var cipherData = sessionCrypter.Encrypt(keyData);
                var session = new CertEncryptedKeySet.SessionPack(sessionMaterial, cipherData);
                var json = Keyczar.Util.Utility.ToJson(session);
                var jsonData = this.GetConfig().RawStringEncoding.GetBytes(json);
                _writer.Write(jsonData, version);
            }
        }

        public void Write(KeyMetadata metadata)
        {
            metadata.Encrypted = true;
            _writer.Write(metadata);
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _certKeySet = _certKeySet.SafeDispose();
                    _encrypter = _encrypter.SafeDispose();
                    _writer = null;
                }
                
                disposedValue = true;
            }
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion

    }
}
