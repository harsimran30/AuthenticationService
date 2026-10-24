using System.Security.Claims;
using AuthenticationService.Managers;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Models
{
    public class JWTContainerModel : IAuthContainerModel
    {
        #region Public Methods
        public int ExpireMinutes { get; set; } = 60; // 1 hour.
        public string SecretKey { get; set; } = GetThumbPrint(); // Thumbprint of the signing certificate (see CertificateLoader).

        private static string GetThumbPrint()
        {
            using (var x509 = CertificateLoader.Load())
                return x509.Thumbprint;
        }

        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.RsaSha256;

        public Claim[] Claims { get; set; }
        #endregion
    }
}
