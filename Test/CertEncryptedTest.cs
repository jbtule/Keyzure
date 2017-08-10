using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using Keyczar;
using Keyzure;
using NUnit.Framework;
using Keyzure.Providers;
using NUnit.Framework.Internal.Filters;

namespace Test
{
    [TestFixture]
    public class CertEncryptedTest:TestBaseHelper
    {
 

    
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
        
        
        [Test]
        public void BasicPfxTestSign()
        {
            var dataPath = Path.Combine(GetTestDirPath(), "rsa-sign-certcrypted");

            var activeSig = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "1.out")).First();
            var primarySig = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "2.out")).First();
            using (var pfxStream = File.OpenRead(PfxPath()))
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(dataPath),
                CertEncryptedKeySet.Creator(pfxStream, ()=> PfxPass)))
            using (var verifier = new Verifier(ks))
            {
                var activeDecrypted = verifier.Verify(Input, activeSig);
                Expect(activeDecrypted, Is.True);
                var primaryDecrypted = verifier.Verify(Input, primarySig);
                Expect(primaryDecrypted, Is.True);
            }
        }
        
        [Test]
        public void BasicPfxTestPublicVerify()
        {
            var dataPath = Path.Combine(GetTestDirPath(), "rsa-sign-certcrypted");
            var keySetPath = Path.Combine(GetTestDirPath(), "rsa-sign-certcrypted.public");
            
            var activeSig = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "1.out")).First();
            var primarySig = (WebBase64) File.ReadAllLines(Path.Combine(dataPath, "2.out")).First();
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(keySetPath)))
            using (var verifier = new Verifier(ks))
            {
                var activeDecrypted = verifier.Verify(Input, activeSig);
                Expect(activeDecrypted, Is.True);
                var primaryDecrypted = verifier.Verify(Input, primarySig);
                Expect(primaryDecrypted, Is.True);
            }
        }

 
    }
}