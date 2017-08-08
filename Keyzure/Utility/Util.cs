using System.Linq;
using Keyczar;
using Keyczar.Crypto;

namespace Keyzure.Utility
{
    public static class Util
    {
        public static Key GetPrimaryKey(this IKeySet keySet)
        {
            var primaryVersion = keySet.Metadata.Versions.SingleOrDefault(it => it.Status == KeyStatus.Primary)?.VersionNumber;
            if (primaryVersion == null)
            {
                return null;
            }
            return keySet.GetKey(primaryVersion.Value);
        }
    }
}