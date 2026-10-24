using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace AuthenticationService.Managers
{
    /// <summary>
    /// Loads the signing certificate (PFX) from configuration supplied through environment variables,
    /// so neither the file path nor its password is stored in source control.
    ///   JWT_CERT_PATH      full path to the .pfx file
    ///   JWT_CERT_PASSWORD  password of the .pfx file
    /// </summary>
    public static class CertificateLoader
    {
        public const string PathVariable = "JWT_CERT_PATH";
        public const string PasswordVariable = "JWT_CERT_PASSWORD";

        public static X509Certificate2 Load()
        {
            string path = Environment.GetEnvironmentVariable(PathVariable);
            string password = Environment.GetEnvironmentVariable(PasswordVariable);

            if (string.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException($"Environment variable {PathVariable} is not set.");

            if (!File.Exists(path))
                throw new FileNotFoundException($"Certificate file specified by {PathVariable} was not found.", path);

            return new X509Certificate2(path, password, X509KeyStorageFlags.PersistKeySet);
        }
    }
}
