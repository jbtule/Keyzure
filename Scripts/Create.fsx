#!/bin/sh
#if run_with_bin_sh
  exec fsharpi --exec $0 $*
#endif
//Run with fsi --exec Create.fsx on windows, or ./Create.fsx on Mac/Linux
//Use this script to create a keyzure store on azure storage

#load "Helper.fsx"

open Keyzure
open Keyczar
open Keyczar.Compat
open System
open System.IO
open System.Security.Cryptography.X509Certificates
open System.Linq
open Microsoft.WindowsAzure.Storage

let connectionString = Helper.readVariable "Enter your azure connection string:" Helper.storageConnectionStringTest

let containerName = Helper.readVariable "Enter Your Azure Container name:" Helper.checkTypedEntry
let containerPath = Helper.readVariable "Enter Your Container Path:" Helper.checkTypedEntry
let name = Helper.readVariable "Name This KeySet:" Helper.checkTypedEntry

let thumbprintOption = Helper.readOptionalVariable "Do you already have a private cert" "Enter Your Thumpprint:" Helper.thumprintExists

let thumbprint =
    if thumbprintOption |> Option.isNone then
        let pfxName = sprintf "%s.pfx" name
        let pfxPath = Path.Combine("Secrets", pfxName)
        let ksm = KeyMetadata(Kind = KeyKind.Private, Purpose = KeyPurpose.DecryptAndEncrypt, Name = pfxName);
        use ks = new MutableKeySet(ksm)
        ks.AddKey(KeyStatus.Primary, keySize=2048) |> ignore
        let pass = Helper.readPassword()
        if not <| ks.ExportAsPkcs12(pfxPath, fun ()-> pass) then
            printfn "Failed to create pfx file %s" pfxPath
            exit -10
        let certBundle = X509Certificate2Collection();
        certBundle.Import(pfxPath, pass, X509KeyStorageFlags.PersistKeySet ||| X509KeyStorageFlags.UserKeySet ||| X509KeyStorageFlags.Exportable);
        let thumb = certBundle.OfType<X509Certificate2>() 
                        |> Seq.filter (fun x-> x.HasPrivateKey)
                        |> Seq.map (fun x-> x.Thumbprint)
                        |> Seq.distinct
                        |> Seq.head
        let cert = certBundle.OfType<X509Certificate2>().First(fun it -> it.HasPrivateKey && it.Thumbprint = thumb)
        use store = new X509Store(StoreName.My, StoreLocation.CurrentUser)
        store.Open(OpenFlags.ReadWrite);
        store.Add(cert)
        store.Close();
        thumb
    else
        thumbprintOption |> Option.get


let storageAccount = CloudStorageAccount.Parse(connectionString)


let kind = Helper.readChoiceFromListValue ["Symetric",KeyKind.Symmetric ; "Asymetric-Private",KeyKind.Private] "Type of Encryption"

let purpose = Helper.readChoiceFromListValue ["Sign & Verify",KeyPurpose.SignAndVerify ; "Encrypt & Decrypt",KeyPurpose.DecryptAndEncrypt] "Purpose of Encryption"

let ksm = KeyMetadata(Kind = kind, Purpose = purpose, Name = name);
let  ks = new MutableKeySet(ksm)


let settingsPath = (Path.Combine("Secrets", sprintf "%s.json" name))
Helper.writeConfig {
                        AzureStorageConnectionString = connectionString
                        AzureContainerName = containerName
                        CertThumbprint = thumbprint
                        KeyzurePath = containerPath
                   } 
                   settingsPath


let layeredWriter = ()
                      |> StorageKeySetWriter.Create(storageAccount, containerName, containerPath).Invoke
                      |> CertEncryptedKeySetWriter.Creator(thumbprint).Invoke

if not <| ks.Save(layeredWriter) then
    Console.WriteLine(sprintf "Failed to create  %s keyset" name)
    exit -10


Console.WriteLine(sprintf "Created Keyset and Saved settings to %s." settingsPath)