#I "../Keyzure/bin/Debug/net46/"
#r "Keyczar.dll"
#r "Keyzure.dll"
#r "Microsoft.WindowsAzure.Storage.dll"
#r "Newtonsoft.Json.dll"

open System
open Microsoft.WindowsAzure.Storage
open System.Security.Cryptography.X509Certificates
open System.Linq
open Newtonsoft.Json
open System.IO

type Config = {
        AzureStorageConnectionString :string
        AzureContainerName:string
        CertThumbprint:string
        KeyzurePath: string
    }

let readConfig = File.ReadAllText >>  JsonConvert.DeserializeObject<Config>

let writeConfig (config:Config) path = (path, (config |> JsonConvert.SerializeObject)) |> File.WriteAllText

let storageConnectionStringTest connString =
    let storageAccount = CloudStorageAccount.Parse(connString)
    let blobClient = storageAccount.CreateCloudBlobClient()
    let mutable token:Blob.BlobContinuationToken = null
    try
        blobClient.ListContainersSegmented(token) |> ignore
        true
    with _ ->   
        Console.WriteLine("Error: Could not connect using the connection string as entered.")
        false

let yesOrNo input =
    Console.Write (sprintf "%s [y]?" input)
    while (not Console.KeyAvailable) do
      System.Threading.Thread.Sleep(500)
    let char = Console.ReadKey(true).Key
    match char with
        | ConsoleKey.Y | ConsoleKey.Enter -> Console.WriteLine("y"); true
        | _______________________________ -> Console.WriteLine("n"); false

let checkTypedEntry input = yesOrNo (sprintf "Confirm '%s'" input)


let checkRetypeInput input = yesOrNo (sprintf "Confirm '%s'" input)

let thumprintExists (input:string) =
    use certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser)
    certStore.Open(OpenFlags.ReadOnly)
    let collect = certStore.Certificates.Find(X509FindType.FindByThumbprint, input, false)
    let found = collect.OfType<X509Certificate2>().Any()
    if found then
        true
    else
        Console.WriteLine("Error: Couldn't find cert matching thumprint in keystore")
        false


let readVariable (question:string) (test:string->bool) =
    let mutable run = true
    let mutable input = ""
    while run do
        Console.WriteLine(question)
        input <- Console.ReadLine()
        run <- input |> test |> not
    input

let readPassword ()=
    let maskPassword () =
        let mutable run = true
        let mutable input = ""
        let start = Console.CursorLeft
        while (run) do
            while (not Console.KeyAvailable) do
                System.Threading.Thread.Sleep(500)
            let keyInfo = Console.ReadKey(true)
            match keyInfo.Key with
                | ConsoleKey.Enter     -> run <- false; Console.WriteLine()
                | ConsoleKey.Backspace -> input <- ""; 
                                          let dist = Console.CursorLeft - start;
                                          Console.CursorLeft<-start;
                                          for i = start to dist do  
                                            Console.Write("\0")
                                          Console.CursorLeft <- start
                | ____________________ -> Console.Write("*")
                                          input <- input + (keyInfo.KeyChar.ToString())
        input
    let mutable matchPass = false;
    let mutable pass1 = ""
    while not matchPass do
        Console.WriteLine("Please type a password:")
        pass1 <- maskPassword()
        Console.WriteLine("Please reenter password:")
        let pass2 = maskPassword()
        matchPass <- pass1 = pass2
        if (not matchPass) then
            Console.WriteLine("Error: Passwords don't match.")
    pass1

let readChoiceFromListIndex (list: string list) (question:string) =
    let canParse input =
        let s,i = Int32.TryParse(input)
        if s && i > 0 && i <= (list |> List.length) then
            true
        else
            Console.WriteLine("Error: Invalid choice.")
            false
    Console.WriteLine(question)
    list |> Seq.mapi(fun i x -> sprintf "  %i. %s" (i+1) x) |> Seq.iter Console.WriteLine
    let choice = readVariable "Choose:" canParse
    let index = Int32.Parse(choice) - 1
    index

let readChoiceFromListValue (list: (string * 'T) list) (question:string) = 
    list.[(readChoiceFromListIndex (list |> List.map fst) question)] |> snd

let readChoiceFromList (list: string list) (question:string) = list.[(readChoiceFromListIndex list question)]

let readOptionalVariable (question1:string) (question2:string) (test:string->bool) =
    if yesOrNo question1 then
        readVariable question2 test |> Some
    else
        None