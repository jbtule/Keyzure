using System;
using System.Collections.Generic;
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
        
 

        
    
        
        
        [TestCase("hmac-sha2-sign", false)]
        [TestCase("rsa-sign-certcrypted", true)]
        public void JWTHSTest(string testDta, bool certCrypted)
        {
            var keySetPath = Path.Combine(GetTestDirPath(), testDta);

            var issueDate = DateTime.UtcNow;
            var expireDate = issueDate.AddDays(1);

            using (var pfxStream = File.OpenRead(PfxPath()))
            {

                var layers = new List<Func<IKeySet, ILayeredKeySet>>();

                if (certCrypted)
                {
                    layers.Add(CertEncryptedKeySet.Creator(pfxStream, () => PfxPass));
                }


                using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(keySetPath), layers.ToArray()))
                using (var jwtVerifier = new JwtVerifier(ks))
                {
                    var signingKey = new KeyzureSigningCredentials(ks);


                    var token = new JwtSecurityToken("http://test.issue", "http://test.audience",
                        new ClaimsIdentity().Claims, issueDate,
                        expireDate, signingKey);

                    var handler = new JwtSecurityTokenHandler();

                    var jwt = handler.WriteToken(token);

                    Console.WriteLine(jwt);

                    var result = jwtVerifier.VerifyCompact(jwt);

                    Expect(result, Is.True);

                }
            }

        }
       
    }
}