using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Managers
{
    class JWTHelper
    {
        /// <summary>
        /// Validate JWT Token
        /// </summary>
        /// <param name="token">Encoded Token</param>
        /// <param name="_issuer"></param>
        /// <param name="_audience"></param>
        /// <returns>True if the Token has been validated successfully</returns>
        private static bool ValidateJWT(string token, string _issuer, string _audience)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");

            // ... Public Key to Validate JWT
            var publicKey = GetKeyfromCertificate(0);

            // ... Token Validation
            var tokenValidation = new TokenValidationParameters
            {
                ValidAudience = _audience,
                ValidIssuer = _issuer,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                IssuerSigningKey = publicKey
            };

            try
            {
                new JwtSecurityTokenHandler().ValidateToken(token, tokenValidation, out SecurityToken newValidatedToken);
                return true;
            }
            catch
            {
                return false;
            }

        }

        /// <summary>
        /// Generate JWT
        /// </summary>
        /// <param name="appID"></param>
        /// <param name="endpoint"></param>
        /// <returns></returns>
        private static string GenerateToken(string appID, string endpoint)
        {
            var jwtHandler = new JwtSecurityTokenHandler();

            // ... Private Key to Sign JWT
            var privatekey = GetKeyfromCertificate();

            // ... Build ClaimSet
            var claimSet = new ClaimsIdentity(new Claim[]
                {
                    new Claim("sub", appID),
                    new Claim("jti", Guid.NewGuid().ToString())
                });

            // ... Token Descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = appID,
                Audience = endpoint,
                NotBefore = DateTime.Now,
                Expires = DateTime.Now.AddMinutes(60),
                Subject = claimSet,
                SigningCredentials = new SigningCredentials(privatekey, SecurityAlgorithms.RsaSha256Signature)
            };

            // ... Build Secure Token
            var secureToken = jwtHandler.CreateToken(tokenDescriptor);
            return jwtHandler.WriteToken(secureToken);
        }

        /// <summary>
        /// Build Keys from certificate
        /// </summary>
        /// <param name="typeKey"></param>
        /// <param name="certificate"></param>
        /// <param name="Pass"></param>
        /// <returns>Returns Private and Public Keys</returns>
        private static RsaSecurityKey GetKeyfromCertificate(int typeKey = 1, string certificate = null, string Pass = null)
        {
            if (certificate == null)
                certificate = @"C:\Users\harsi\Desktop\Azure - CDH\privatekey-9650.pfx";

            if (Pass == null)
                Pass = "Pass-123";

            // ... Certificate for keys
            X509Certificate2 x509 = new X509Certificate2(certificate, Pass);

            // ... Private Key to Sign JWT
            var privatekey = x509.GetRSAPrivateKey();

            // ... Public Key to Validate JWT
            var publicKey = x509.GetRSAPublicKey();

            return new RsaSecurityKey(typeKey == 1 ? privatekey : publicKey);
        }
    }
}
