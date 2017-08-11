using Keyczar;
using Keyczar.Unofficial;
using Microsoft.IdentityModel.Tokens;

namespace Keyzure.Providers
{
    public class KeyzureSigningCredentials : SigningCredentials
    {
    
        public KeyzureSigningCredentials(IKeySet keySet)
            : base(new KeySetKey(keySet), Jwt.AlgForKey(keySet.GetPrimaryKey())?.ToString())
        {
        }
    }
}