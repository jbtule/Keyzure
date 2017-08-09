using System.Linq;
using Keyczar;
using Keyczar.Crypto;

namespace Keyzure.Utility
{
    public static class Util
    {
        public static Key GetPrimaryKey(this IKeySet keySet)
        {
            var primaryKeyVersion = keySet.Metadata.GetPrimaryKeyVersion();
            return primaryKeyVersion == null 
                ?  null 
                : keySet.GetKey(primaryKeyVersion.VersionNumber);
        }
    }
}