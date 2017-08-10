using System.IO;
using System.Reflection;
using NUnit.Framework;

namespace Test
{
    public class TestBaseHelper: AssertionHelper
    {
        public  static string GetTestDirPath()
        {
            var location = Assembly.GetAssembly(typeof(CertEncryptedTest)).Location;
            var testDir = Path.Combine(location,"..", "..", "..", "..", "..", "TestData");
            return Path.GetFullPath(testDir);
        }

        public static string PfxPath() => Path.Combine(GetTestDirPath(), "cert", "private.pfx");

        public static string PfxPass => "test";
        public static string Input => "This is some test data";
    }
}