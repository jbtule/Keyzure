using Keyczar;
using Microsoft.IdentityModel.Tokens;

namespace Keyzure.Providers
{
    public class KeyzureSigningCredentials : SigningCredentials
    {
    
        public KeyzureSigningCredentials(IKeySet keySet)
            : base(new KeySetKey(keySet), KeyzureCryptoProvider.GetAlgorithmFromKeySet(keySet))
        {
        }
    }
}