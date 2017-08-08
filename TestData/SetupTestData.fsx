#!/bin/sh
#if run_with_bin_sh
  exec fsharpi --exec $0 $*
#endif

#I "../Keyzure/bin/Debug/net46/"
#r "Keyczar.dll"
#r "Keyzure.dll"

open Keyczar
open Keyczar.Compat
open Keyzure
open System.IO;
open System.Security.Cryptography.X509Certificates;
open System.Linq
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


let aesgcmPath = "aes-gcm-certcrypted"
if not <| Directory.Exists(aesgcmPath) then
    printfn "Creating %s keyset & samples" aesgcmPath
    Directory.CreateDirectory(aesgcmPath) |> ignore
    use pfxRaed = File.OpenRead(pfxPath)
    use layeredWriter = ()
                          |> FileSystemKeySetWriter.Creator(aesgcmPath).Invoke
                          |> CertEncryptedKeySetWriter.Creator(pfxRaed,fun ()-> "test").Invoke
    let ksm = KeyMetadata(Kind = KeyKind.Symmetric, Purpose = KeyPurpose.DecryptAndEncrypt, Name ="aes-gcm");
    use ks = new MutableKeySet(ksm)
    ks.AddKey(KeyStatus.Primary) |> ignore
    use crypter1 = new Encrypter(ks)
    File.WriteAllText(Path.Combine(aesgcmPath, "1.out"), crypter1.Encrypt(input).ToString())
    ks.AddKey(KeyStatus.Primary) |> ignore
    use crypter2 = new Encrypter(ks)
    File.WriteAllText(Path.Combine(aesgcmPath, "2.out"), crypter2.Encrypt(input).ToString())
    if not <| ks.Save(layeredWriter) then
        printfn "Failed to create  %s keyset & samples" aesgcmPath
        exit -10





