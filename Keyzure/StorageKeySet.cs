using System;
using System.IO;
using Keyczar;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using System.Globalization;

namespace Keyzure
{
    public class StorageKeySet : IRootProviderKeySet
    {
        public static Func<StorageKeySet> Create(CloudStorageAccount account, string container, string keySetPath,
            BlobRequestOptions options = null) => () => new StorageKeySet(account, container, keySetPath, options);


        public StorageKeySet(CloudStorageAccount account, string container, string keySetPath, BlobRequestOptions options = null)
        {
            _client = account.CreateCloudBlobClient();
            _container = _client.GetContainerReference(container);
            _keySetPath = keySetPath;
            _options = options;
        }

        public KeyMetadata Metadata => KeyMetadata.Read(Keyczar.Keyczar.RawStringEncoding.GetString(GetFile("meta")));

        public byte[] GetKeyData(int version) => GetFile(version.ToString(CultureInfo.InvariantCulture));

     
        private CloudBlobClient _client;
        private CloudBlobContainer _container;
        private string _keySetPath;
        private BlobRequestOptions _options;

        protected byte[] GetFile(string filename)
        {
            using (var stream = new MemoryStream())
            {
                var path = Path.Combine(_keySetPath, filename).Replace(Path.DirectorySeparatorChar, '/');
                var blockBlob = _container.GetBlockBlobReference(path);
                blockBlob.DownloadToStream(stream, options: _options);
                return stream.ToArray();
            }
        }
        
        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls
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
