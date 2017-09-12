using System;
using System.Collections.Generic;
using System.Data;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Keyczar;
using Keyczar.Util;
using Microsoft.Rest;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;

namespace Keyzure
{
    public class StorageKeySetWriter:IRootProviderKeySetWriter
    {      
        public static Func<StorageKeySetWriter> Create(CloudStorageAccount account, string container, string keySetPath,
            BlobRequestOptions options = null) => () => new StorageKeySetWriter(account, container, keySetPath, options);

        private CloudBlobClient _client;
        private CloudBlobContainer _container;
        private string _keySetPath;
        private BlobRequestOptions _options;
        private List<Exception> _exceptions = new List<Exception>();

        public StorageKeySetWriter(CloudStorageAccount account, string container, string keySetPath, BlobRequestOptions options = null)
        {
            _client = account.CreateCloudBlobClient();
            _container = _client.GetContainerReference(container);
            _container.CreateIfNotExists();
            _keySetPath = keySetPath;
            _options = options;
            _guid = Guid.NewGuid().ToString();
            _success = true;
        }
        
        protected void WriteFile(string filename, byte[] data)
        {
            try
            {
                using (var stream = new MemoryStream(data))
                {
                    var path = Path.Combine(_keySetPath, _guid, filename).Replace(Path.DirectorySeparatorChar, '/');
                    var blockBlob = _container.GetBlockBlobReference(path);
                    blockBlob.UploadFromStream(stream, options: _options);
                }
            }
            catch(Exception ex)
            {               
                _exceptions.Add(ex);
                _success = false;
            }
        }
 
        public void Write(byte[] keyData, int version) 
            => WriteFile(version.ToString(CultureInfo.InvariantCulture), keyData);

        public void Write(KeyMetadata metadata) 
            => WriteFile("meta", this.GetConfig().RawStringEncoding.GetBytes(metadata.ToJson()));

        public bool Finish()
        {
            var guidDir = Path.Combine(_keySetPath, _guid).Replace(Path.DirectorySeparatorChar, '/');
            var directory = _container.GetDirectoryReference(guidDir);
            var blobs = directory.ListBlobs(options:_options).ToList().OfType<CloudBlockBlob>().ToList();
            
            if (_success)
            {
                var tasks = new List<Task>();
                var copyBlobs = new List<CloudBlob>();
                foreach (var blob in blobs)
                {
                    var filename = Path.GetFileName(blob.Name);
                    var path = Path.Combine(_keySetPath, filename).Replace(Path.DirectorySeparatorChar, '/');
                    var blobCopy = _container.GetBlockBlobReference(path);
                    tasks.Add(blobCopy.StartCopyAsync(blob));
                    copyBlobs.Add(blobCopy);
                }
                Task.WaitAll(tasks.ToArray());
                Task.WaitAll(copyBlobs.Select(WaitForCopyAsync).ToArray());
                var badCopies = copyBlobs.Where(b=>b.CopyState.Status != CopyStatus.Success).ToList();
                if (badCopies.Any())
                {
                    
                    throw new AggregateException(
                        badCopies.Select(badCopy=>
                            new HttpOperationException($"Finalizing keyset Failed for {badCopy.Name}: {badCopy.CopyState.StatusDescription}")));
                }
            }
            
            var deleteTasks = new List<Task>();
            foreach (var blob in blobs)
            {
                deleteTasks.Add(blob.DeleteAsync());
            }
            Task.WaitAll(deleteTasks.ToArray());
            
            
            Exception newEx = null;
            if (_exceptions.Any())
                newEx = new AggregateException(_exceptions);

            _exceptions.Clear();

            if (newEx != null)
                throw newEx;

            return _success;
        }

        public KeyczarConfig Config { get; set; }


        public static async Task WaitForCopyAsync(CloudBlob blob)
        {
            var copyInProgress = true;
            while (copyInProgress)
            {
                await Task.Delay(1000);
                await blob.FetchAttributesAsync();
                copyInProgress = (blob.CopyState.Status == CopyStatus.Pending);
            }
        }
        
        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls
        private string _guid;
        private bool _success;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    _client = null;
                    _container = null;
                    _options = null;
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }


        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
        }
        #endregion
    }
}
