using System;
using System.Linq;
using Keyczar;
using Keyzure;
using Microsoft.WindowsAzure.Storage;
using NUnit.Framework;

namespace Test
{
    [TestFixture(Category = "AzureEmulator")]
    [NonParallelizable]
    [Platform(Include = "Win")]
    public class StorageTests:AssertionHelper
    {
        public static readonly string DefaultContainer = "keyzure-test";
        public static string Input => "This is some test data";
        private bool _wasUp;

        [OneTimeSetUp]
        public void Init()
        {
            if (!AzureStorageEmulatorManager.IsProcessStarted())
            {
                AzureStorageEmulatorManager.StartStorageEmulator();
                _wasUp = false;
            }
            else
            {
                _wasUp = true;
            }
        }

        [OneTimeTearDown]
        public void Cleanup()
        {
            if (!_wasUp)
            {
                AzureStorageEmulatorManager.StopStorageEmulator();
            }
        }
        
        private CloudStorageAccount GetClientCred()
        {
            return CloudStorageAccount.Parse("UseDevelopmentStorage=true");
        }
        
        private StorageKeySetWriter CreateNewStorageWriter(string containerName, string keySetPath)
        {
            var storageAccount = GetClientCred();
            var blobClient = storageAccount.CreateCloudBlobClient();
            var container = blobClient.GetContainerReference(containerName);
            container.CreateIfNotExists();


            return StorageKeySetWriter.Create(storageAccount, containerName, keySetPath)();
        }
       
        private MutableKeySet CreateNewKeySetMeta(KeyKind type, KeyPurpose purpose, string name = null)
        {
            return new MutableKeySet(new KeyMetadata
            {
                Name = name ?? "Test",
                Purpose = purpose,
                Kind = type
            });
        }
        
        [Test,Order(1)]
        public void Create()
        {
            using( var baseWriter = CreateNewStorageWriter(DefaultContainer, "create1"))
            using (var mks = CreateNewKeySetMeta(KeyKind.Symmetric, KeyPurpose.DecryptAndEncrypt, "Create1"))
            {
                var success = mks.Save(baseWriter);
                Expect(success, Is.True);
            }
            
        }
        
        [Test,Order(2)]
        public void ReadMeta()
        {
            using( var ks = StorageKeySet.Create(GetClientCred(), DefaultContainer, "create1")())
            {
                Expect(ks.Metadata.Name, Is.EqualTo("Create1"));
            }
        }
        
        [Test,Order(3)]
        public void CreateNoPrimary()
        {
            using (var writer =  CreateNewStorageWriter(DefaultContainer, "no-primary") )
            using (var ks = CreateNewKeySetMeta(KeyKind.Symmetric, KeyPurpose.DecryptAndEncrypt))
            {
                int ver = ks.AddKey(KeyStatus.Primary);
                Expect(ver, Is.EqualTo(1));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

                WebBase64 cipherText = null;
            
                using (var origKs = new StorageKeySet(GetClientCred(), DefaultContainer, "no-primary"))
                using (var encrypter = new Encrypter(origKs))
                {
                    cipherText = encrypter.Encrypt(Input);
                }
                    
                using (var origKs = new StorageKeySet(GetClientCred(), DefaultContainer, "no-primary"))
                using (var ks = new MutableKeySet(origKs))
                using (var writer =  CreateNewStorageWriter(DefaultContainer, "no-primary") )
                {
                    var status = ks.Demote(1);
                    Expect(status, Is.EqualTo(KeyStatus.Active));

                    var success = ks.Save(writer);
                    Expect(success, Is.True);
                }
                
                using (var origKs = new StorageKeySet(GetClientCred(), DefaultContainer, "no-primary"))
                using (var crypter = new Crypter(origKs))
                {
                    var output = crypter.Decrypt(cipherText);
                    Expect(output, Is.EqualTo(Input));
                }
                    
            
        }
        
        
        [Test,Order(4)]
        public void RevokeOverwrite()
        {
            var testPath = "revoke-override";
            
            using (var writer =  CreateNewStorageWriter(DefaultContainer, testPath) )
            using (var ks = CreateNewKeySetMeta(KeyKind.Symmetric, KeyPurpose.DecryptAndEncrypt))
            {
                int ver = ks.AddKey(KeyStatus.Primary);
                Expect(ver, Is.EqualTo(1));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }

            WebBase64 origCipherText = null;
            WebBase64 origKeyId = null;
            using (var ks = new StorageKeySet(GetClientCred(), DefaultContainer, testPath))
            using (var encrypter = new Encrypter(ks))
            {
                origCipherText = encrypter.Encrypt(Input);
                origKeyId = WebBase64.FromBytes(ks.Metadata.Versions.First().KeyId);
            }
                    
            using (var origKs = new StorageKeySet(GetClientCred(), DefaultContainer, testPath))
            using (var ks = new MutableKeySet(origKs))
            using (var writer =  CreateNewStorageWriter(DefaultContainer, testPath) )
            {
                var status = ks.Demote(1);
                Expect(status, Is.EqualTo(KeyStatus.Active));

                var status2 = ks.Demote(1);
                Expect(status2, Is.EqualTo(KeyStatus.Inactive));
                
                var revoked = ks.Revoke(1);
                Expect(revoked, Is.True);
                
                var success = ks.Save(writer);
                Expect(success, Is.True);
            }
            
            using (var writer =  CreateNewStorageWriter(DefaultContainer, testPath) )
            using (var ks = CreateNewKeySetMeta(KeyKind.Symmetric, KeyPurpose.DecryptAndEncrypt))
            {
                int ver = ks.AddKey(KeyStatus.Primary);
                Expect(ver, Is.EqualTo(1));

                var success = ks.Save(writer);
                Expect(success, Is.True);
            }
                
            WebBase64 newCipherText = null;

            using (var ks = new StorageKeySet(GetClientCred(), DefaultContainer, testPath))
            using (var encrypter = new Encrypter(ks))
            {
                newCipherText = encrypter.Encrypt(Input);
            }
            
            using( var ks = StorageKeySet.Create(GetClientCred(), DefaultContainer, testPath)())
            {
                var newKeyId = WebBase64.FromBytes(ks.Metadata.Versions.First().KeyId);
                var prefix = new byte[KeyczarConst.HeaderLength];
                Array.Copy(newCipherText.ToBytes(),prefix, prefix.Length);
                Expect(prefix, Is.Not.EqualTo(origKeyId.ToBytes()));
                Expect(prefix, Is.EqualTo(newKeyId.ToBytes()));

            } 
            
        }
    }
}