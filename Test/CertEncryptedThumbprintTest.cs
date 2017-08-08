using System;
using System.IO;
using System.Linq;
using System.Reflection;
using Keyczar;
using Keyzure;
using Microsoft.WindowsAzure.Storage;
using NUnit.Framework;
using System.Security.Cryptography.X509Certificates;

namespace Test
{
    [TestFixture]   
    [Platform(Include = "Win")]
    public class CertEncryptedThumbprintTest:AssertionHelper
    {
        private string GetTestDirPath()
        {
            var location = Assembly.GetAssembly(this.GetType()).Location;
            var testDir = Path.Combine(location,"..", "..", "..", "..", "..", "TestData");
            return Path.GetFullPath(testDir);
        }

        private string GetThumbprint() => File.ReadAllText(Path.Combine(GetTestDirPath(), "cert", "thumbprint.txt")).Trim();

        private X509Certificate2 GetCert()
        {
            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            var thumbPrint = GetThumbprint();
            var certCollection = certStore.Certificates.Find(X509FindType.FindByThumbprint, thumbPrint, false);
            return certCollection.OfType<X509Certificate2>().FirstOrDefault();
        }


        [OneTimeSetUp]
        public void Init()
        {
            var cert = GetCert();
            if (cert == null)
            {
                var certBundle = new X509Certificate2Collection();
                certBundle.Import(CertEncryptedTest.PfxPath(),CertEncryptedTest.PfxPass,
                    X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);
                var cert2 = certBundle.OfType<X509Certificate2>().First(it => it.HasPrivateKey && it.Thumbprint == GetThumbprint());
                var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert2);
                store.Close();
                cert = GetCert();
            }
            if(cert == null)
            {
                throw new Exception("Unable to load cert into store");
            }
        }
        
        [Test]
        [Platform(Include = "Win")]
        public void BasicThumbprintTest()
        {
            var dataPath = Path.Combine(GetTestDirPath(), "aes-gcm-certcrypted");

            var activeCiphertext = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "1.out")).First();
            var primaryCiphertext = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "2.out")).First();
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(dataPath),
                CertEncryptedKeySet.Creator(GetThumbprint())))
            using (var crypter = new Crypter(ks))
            {
                var activeDecrypted = crypter.Decrypt(activeCiphertext);
                Expect(activeDecrypted, Is.EqualTo(CertEncryptedTest.Input));
                var primaryDecrypted = crypter.Decrypt(primaryCiphertext);
                Expect(primaryDecrypted, Is.EqualTo(CertEncryptedTest.  Input));
            }
        }
    }
}