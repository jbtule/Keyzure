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

        [Test]
        public void JWTTest()
        {
            var keySetPath = Path.Combine(GetTestDirPath(), "rsa-sign-certcrypted");

            var issueDate = DateTime.UtcNow;
            var expireDate = issueDate.AddDays(1);
            
            using (var pfxStream = File.OpenRead(PfxPath()))
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(keySetPath),
                CertEncryptedKeySet.Creator(pfxStream, ()=> PfxPass)))
            {
                var signingKey = new KeyzureSigningCredentials(ks);


                var token = new JwtSecurityToken("http://test.issue", "http://test.audience", new ClaimsIdentity().Claims , issueDate,
                    expireDate, signingKey);

                var handler = new JwtSecurityTokenHandler();

                var jwt = handler.WriteToken(token);
                
                Console.WriteLine(jwt);
            }

        }
       
    }
}