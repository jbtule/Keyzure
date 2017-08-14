#!/bin/sh
#if run_with_bin_sh
  exec fsharpi --exec $0 $*
#endif
//Run with fsi --exec SetupTestData.fsx on windows, or ./SetupTestData.fsx on Mac/Linux
//Use this script to regenerate TestData and certs


#I "../Keyzure/bin/Debug/net46/"
#r "Keyczar.dll"
#r "Keyzure.dll"

open Keyczar
open Keyczar.Compat
open Keyzure
open System
open System.IO
open System.Security.Cryptography.X509Certificates
open System.Linq
open Keyczar.Unofficial
open System.Text

let input = "This is some test data"
let certDir = "cert"
Directory.CreateDirectory(certDir) |> ignore
let pfxPath = Path.Combine(certDir, "private.pfx")
if not <| File.Exists(pfxPath) then
    printfn "Creating %s" pfxPath
    let ksm = KeyMetadata(Kind = KeyKind.Private, Purpose = KeyPurpose.DecryptAndEncrypt, Name ="private.pfx");
    use ks = new MutableKeySet(ksm)
    ks.AddKey(KeyStatus.Primary, keySize=2048) |> ignore
    if not <| ks.ExportAsPkcs12(pfxPath, fun ()-> "test") then
        printfn "Failed to create pfx file %s" pfxPath
        exit -10
    let certBundle = X509Certificate2Collection();
    certBundle.Import(pfxPath, "test", X509KeyStorageFlags.DefaultKeySet);
    certBundle.OfType<X509Certificate2>() 
                    |> Seq.filter (fun x-> x.HasPrivateKey)
                    |> Seq.map (fun x-> x.Thumbprint)
                    |> Seq.distinct
                    |> fun x -> File.WriteAllLines(Path.Combine(certDir, "thumbprint.txt"), x)

do
    let keySetAndDataPath = "aes-gcm-certcrypted"
    let name = "aes-gcm"
    let kind = KeyKind.Symmetric
    let purpose = KeyPurpose.DecryptAndEncrypt;
    if not <| Directory.Exists(keySetAndDataPath) then
        printfn "Creating %s keyset & samples" keySetAndDataPath
        Directory.CreateDirectory(keySetAndDataPath) |> ignore
        use pfxRead = File.OpenRead(pfxPath)
        use layeredWriter = ()
                              |> FileSystemKeySetWriter.Creator(keySetAndDataPath).Invoke
                              |> CertEncryptedKeySetWriter.Creator(pfxRead,fun ()-> "test").Invoke
        let ksm = KeyMetadata(Kind = kind, Purpose = purpose, Name = name);
        use ks = new MutableKeySet(ksm)
        ks.AddKey(KeyStatus.Primary) |> ignore
        use crypter1 = new Encrypter(ks)
        File.WriteAllText(Path.Combine(keySetAndDataPath, "1.out"), crypter1.Encrypt(input).ToString())
        ks.AddKey(KeyStatus.Primary) |> ignore
        use crypter2 = new Encrypter(ks)
        File.WriteAllText(Path.Combine(keySetAndDataPath, "2.out"), crypter2.Encrypt(input).ToString())
        if not <| ks.Save(layeredWriter) then
            printfn "Failed to create  %s keyset & samples" keySetAndDataPath
            exit -10
do
    let keySetAndDataPath = "rsa-sign-certcrypted"
    let name = "rsa-sign"
    let kind = KeyKind.Private
    let purpose = KeyPurpose.SignAndVerify
    let size = 3072;
    if not <| Directory.Exists(keySetAndDataPath) then
        printfn "Creating %s keyset & samples" keySetAndDataPath
        Directory.CreateDirectory(keySetAndDataPath) |> ignore
        use pfxRead = File.OpenRead(pfxPath)
        use layeredWriter = ()
                              |> FileSystemKeySetWriter.Creator(keySetAndDataPath).Invoke
                              |> CertEncryptedKeySetWriter.Creator(pfxRead,fun ()-> "test").Invoke
        let ksm = KeyMetadata(Kind = kind, Purpose = purpose, Name = name);
        use ks = new MutableKeySet(ksm)
        ks.AddKey(KeyStatus.Primary, size) |> ignore
        use signer1 = new Signer(ks)
        File.WriteAllText(Path.Combine(keySetAndDataPath, "1.out"), signer1.Sign(input).ToString())
        ks.AddKey(KeyStatus.Primary, size) |> ignore
        use signer2 = new Signer(ks)
        File.WriteAllText(Path.Combine(keySetAndDataPath, "2.out"), signer2.Sign(input).ToString())
        if not <| ks.Save(layeredWriter) then
            printfn "Failed to create  %s keyset & samples" keySetAndDataPath
            exit -10
        ks.ExportPrimaryAsPkcs(Path.Combine(keySetAndDataPath, "primary.pem"), null) |> ignore

        let pubKeySetAndDataPath = keySetAndDataPath + ".public"
        Directory.CreateDirectory(pubKeySetAndDataPath) |> ignore
        let pubks = ks.PublicKey()
        use pubWriter = FileSystemKeySetWriter.Creator(pubKeySetAndDataPath).Invoke()
        if not <| ks.Save(pubWriter) then
            printfn "Failed to create  %s keyset & samples" keySetAndDataPath
            exit -10
do
    let keySetAndDataPath = "hmac-sha2-sign"
    let name = "hmac-sha2-sign"
    let kind = KeyKind.Symmetric
    let purpose = KeyPurpose.SignAndVerify
    let size = 128;
    if not <| Directory.Exists(keySetAndDataPath) then
        printfn "Creating %s keyset & samples" keySetAndDataPath
        Directory.CreateDirectory(keySetAndDataPath) |> ignore
        use pfxRead = File.OpenRead(pfxPath)
        use layeredWriter = ()
                              |> FileSystemKeySetWriter.Creator(keySetAndDataPath).Invoke
        let ksm = KeyMetadata(Kind = kind, Purpose = purpose, Name = name);
        use ks = new MutableKeySet(ksm)
        ks.AddKey(KeyStatus.Primary, size) |> ignore
        use signer1 = new Signer(ks)
        File.WriteAllText(Path.Combine(keySetAndDataPath, "1.out"), signer1.Sign(input).ToString())
        ks.AddKey(KeyStatus.Primary, size) |> ignore
        use signer2 = new Signer(ks)
        File.WriteAllText(Path.Combine(keySetAndDataPath, "2.out"), signer2.Sign(input).ToString())
        if not <| ks.Save(layeredWriter) then
            printfn "Failed to create  %s keyset & samples" keySetAndDataPath
            exit -10

do 
        let keySetAndDataPath = Path.Combine("jwt.io", "hs256")
        let name = "hmac-sha2-secret"
        let kind = KeyKind.Symmetric
        let purpose = KeyPurpose.SignAndVerify
        let size = 128;
        if not <| Directory.Exists(keySetAndDataPath) then
            printfn "Creating %s keyset & samples" keySetAndDataPath
            Directory.CreateDirectory(keySetAndDataPath) |> ignore
            use layeredWriter = ()
                              |> FileSystemKeySetWriter.Creator(keySetAndDataPath).Invoke
            use hmackey = new HmacSha2Key(HmacKeyBytes= Encoding.UTF8.GetBytes("secret"),Digest = DigestAlg.Sha256, HashLength = 32 )
            let ksm = KeyMetadata(Kind = kind, Purpose = purpose, Name = name);
            use ks = new MutableKeySet(ksm)
            ks.AddKey(KeyStatus.Primary, hmackey, comment="Test key from jwt.io") |>ignore
            if not <| ks.Save(layeredWriter) then
                printfn "Failed to create  %s keyset & samples" keySetAndDataPath
                exit -10
do 
        let keySetAndDataPath = Path.Combine("jwt.io", "rs256.pub")
        let name = "rsa-pub-import"
        let purpose = KeyPurpose.Verify
        let size = 128;
        let kind = KeyKind.Public

        if not <| Directory.Exists(keySetAndDataPath) then
            printfn "Creating %s keyset & samples" keySetAndDataPath
            Directory.CreateDirectory(keySetAndDataPath) |> ignore
            use layeredWriter = ()
                              |> FileSystemKeySetWriter.Creator(keySetAndDataPath).Invoke
            use iks = ImportedKeySet.Import.PkcsKey(purpose, Path.Combine("jwt.io","rsapub.pem"), official= false, hint = UnofficialKeyType.RSAPubPkcs15Sign)
            let ksm = KeyMetadata(Kind = kind, Purpose = purpose, Name = name);
            use ks = new MutableKeySet(ksm)
            use rsakey = iks.GetPrimaryKey() :?> RsaPublicSignPkcs15Key;
            rsakey.Digest <- DigestAlg.Sha256;
            ks.AddKey(KeyStatus.Primary, rsakey, comment="Test key from jwt.io") |>ignore
            if not <| ks.Save(layeredWriter) then
                printfn "Failed to create  %s keyset & samples" keySetAndDataPath
                exit -10

                
