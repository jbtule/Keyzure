using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Claims;
using Keyczar;
using Keyczar.Unofficial;
using Keyzure;
using Keyzure.Providers;
using Keyzure.Utility;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;

namespace Test
{
    public class JWTTest:TestBaseHelper
    {
        
 
        [TestCase("hs256", false)]
        [TestCase("rs256", true)]
        public void JWTIOVerifyKeyczarTest(string testData, bool pub)
        {
            var dataPath = Path.Combine(GetTestDirPath(), "jwt.io", testData +".jwt");
            var keySetPath = Path.Combine(GetTestDirPath(), "jwt.io", pub ? testData + ".pub" : testData);
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(keySetPath)))
            using (var jwtVerifier = new JwtVerifier(ks))
            {

                var jwt = File.ReadAllText(dataPath).Trim();
                
                var result = jwtVerifier.VerifyCompact(jwt);

                Expect(result, Is.True);

            }
        }
        
        [TestCase("hs256", false)]
        [TestCase("rs256", true)]
        public void JWTIOVerifyOwinTest(string testData, bool pub)
        {
            var dataPath = Path.Combine(GetTestDirPath(), "jwt.io", testData +".jwt");
            var keySetPath = Path.Combine(GetTestDirPath(), "jwt.io", pub ? testData + ".pub" : testData);
            using (var ks = KeySet.LayerSecurity(FileSystemKeySet.Creator(keySetPath)))
           {

                var jwt = File.ReadAllText(dataPath).Trim();
                
                var handler = new JwtSecurityTokenHandler();

               var param = new TokenValidationParameters
               {
                   IssuerSigningKey = new KeySetKey(ks),
                   ValidateLifetime = false,
                   ValidateAudience = false,
                   ValidateIssuer =  false,
               };
               var result = handler.ValidateToken(jwt, param, out var token);

                Expect(result, Is.Not.Null);

            }
        }
        
    
    
        
        
        [TestCase("hmac-sha2-sign", false)]
        [TestCase("rsa-sign-certcrypted", true)]
        public void JWTBasicSignTest(string testDta, bool certCrypted)
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
        
        
           
        
        [TestCase("hmac-sha2-sign", false)]
        [TestCase("rsa-sign-certcrypted", true)]
        public void JWTBasicVerifyTest(string testDta, bool certCrypted)
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
                {
                    var signingKey = new KeyzureSigningCredentials(ks);


                    var token = new JwtSecurityToken("http://test.issue", "http://test.audience",
                        new ClaimsIdentity().Claims, issueDate,
                        expireDate, signingKey);

                    var handler = new JwtSecurityTokenHandler();

                    var jwt = handler.WriteToken(token);

                    Console.WriteLine(jwt);

                    var param = new TokenValidationParameters
                    {
                        IssuerSigningKey = new KeySetKey(ks),
                        ValidAudience = "http://test.audience",
                        ValidIssuer = "http://test.issue",
                    };

                    var result = handler.ValidateToken(jwt, param, out var token2);

                    Expect(result, Is.Not.Null);
                }
            }

        }
       
    }
}