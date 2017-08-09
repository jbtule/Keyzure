using Keyczar;
using Keyzure.Utility;
using Microsoft.IdentityModel.Tokens;

namespace Keyzure.Providers
{
    public class KeySetKey : SecurityKey
    {
        public IKeySet KeySet { get; }

        public KeySetKey(IKeySet keySet)
        {
            KeySet = keySet;
            var primaryKey = keySet.GetPrimaryKey();
            KeyId = KeySet.Metadata.Name;
            KeySize = primaryKey?.Size ?? -1;
            CryptoProviderFactory.CustomCryptoProvider = new KeyzureCryptoProvider();
        }

        public override int KeySize { get; }
    }
}