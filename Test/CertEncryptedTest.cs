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
    public class CertEncryptedTest:AssertionHelper
    {
        public  static string GetTestDirPath()
        {
            var location = Assembly.GetAssembly(typeof(CertEncryptedTest)).Location;
            var testDir = Path.Combine(location,"..", "..", "..", "..", "..", "TestData");
            return Path.GetFullPath(testDir);
        }

        public static string PfxPath() => Path.Combine(GetTestDirPath(), "cert", "private.pfx");

        public static string PfxPass => "test";
        public static string Input => "This is some test data";

    
        [Test]
        public void BasicPfxTest()
        {
            var dataPath = Path.Combine(GetTestDirPath(), "aes-gcm-certcrypted");

            var activeCiphertext = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "1.out")).First();
            var primaryCiphertext = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "2.out")).First();
            using (var pfxStream = File.OpenRead(PfxPath()))
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(dataPath),
                CertEncryptedKeySet.Creator(pfxStream, ()=> PfxPass)))
            using (var crypter = new Crypter(ks))
            {
                var activeDecrypted = crypter.Decrypt(activeCiphertext);
                Expect(activeDecrypted, Is.EqualTo(Input));
                var primaryDecrypted = crypter.Decrypt(primaryCiphertext);
                Expect(primaryDecrypted, Is.EqualTo(Input));
            }
        }
       
    }
}