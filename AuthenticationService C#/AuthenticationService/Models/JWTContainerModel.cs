using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Models
{
    public class JWTContainerModel : IAuthContainerModel
    {
        #region Public Methods
        public int ExpireMinutes { get; set; } = 60; // 1 hour.
        public string SecretKey { get; set; } = GetThumbPrint(); // This secret key should be moved to some configurations outter server.

        private static string GetThumbPrint()
        {
            X509Certificate2 x509 = new X509Certificate2(@"C:\Users\harsi\Desktop\Azure - CDH\privatekey-9650.pfx", "Pass-123",   X509KeyStorageFlags.PersistKeySet);
            return x509.Thumbprint;
        }
        
        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.RsaSha256;

        public Claim[] Claims { get; set; }
        #endregion
    }
}
