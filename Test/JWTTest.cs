using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Security.Claims;
using Keyczar;
using Keyczar.Unofficial;
using Keyzure;
using Keyzure.Providers;
using Keyzure.Utility;
using NUnit.Framework;

namespace Test
{
    public class JWTTest:TestBaseHelper
    {
        
 

        
        [Test]
        public void JWTPSTest()
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
        
        [Test]
        public void JWTHSTest()
        {
            var keySetPath = Path.Combine(GetTestDirPath(), "hmac-sha2-sign");

            var issueDate = DateTime.UtcNow;
            var expireDate = issueDate.AddDays(1);
            
            using (var pfxStream = File.OpenRead(PfxPath()))
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(keySetPath)))
            {
                var signingKey = new KeyzureSigningCredentials(ks);


                var token = new JwtSecurityToken("http://test.issue", "http://test.audience", new ClaimsIdentity().Claims , issueDate,
                    expireDate, signingKey);

                var handler = new JwtSecurityTokenHandler();

                var jwt = handler.WriteToken(token);
                
                Console.WriteLine(jwt);
                Console.WriteLine(WebBase64.FromBytes((ks.GetPrimaryKey() as HmacSha2Key).HmacKeyBytes));
            }

        }
       
    }
}