using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using AuthenticationService.Models;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Managers
{
    public class JWTService : IAuthService
    {
        #region Members
        /// <summary>
        /// The secret key we use to encrypt out token with.
        /// </summary>
        public string SecretKey { get; set; }

        X509Certificate2 certificate = new X509Certificate2(@"C:\Users\harsi\Desktop\Azure - CDH\privatekey-9650.pfx", "Pass-123", X509KeyStorageFlags.PersistKeySet);

        //JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        JsonWebTokenHandler jsontoken = new JsonWebTokenHandler();

        #endregion

        #region Constructor
        public JWTService(string secretKey)
        {
            SecretKey = secretKey;
        }
        #endregion

        #region Public Methods
        /// <summary>
        /// Validates whether a given token is valid or not, and returns true in case the token is valid otherwise it will return false;
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public bool IsTokenValid(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();
            try
            {
                ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                //var valid = jsontoken.ValidateToken(token, tokenValidationParameters);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Generates token by given model.
        /// Validates whether the given model is valid, then gets the assymmetric private key.
        /// Encrypt the token and returns it.
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Generated token.</returns>
        public string GenerateToken(IAuthContainerModel model)
        {
            if (model == null || model.Claims == null || model.Claims.Length == 0 || model.SecretKey == null)
                throw new ArgumentException("Arguments to create token are not valid.");


            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = "Audience",
                Issuer = "Issuer",
                AdditionalHeaderClaims = new Dictionary<string, object>() { { "x5ts", SecretKey } },
                NotBefore = DateTime.Now,
                Expires = DateTime.Now.AddMinutes(Convert.ToInt32(model.ExpireMinutes)),
                Subject = new ClaimsIdentity(model.Claims),
                SigningCredentials = new SigningCredentials(GetPrivateKeyfromCertificate(), model.SecurityAlgorithm)
            };

            //var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            //string token = jwtSecurityTokenHandler.WriteToken(securityToken);

            var token = jsontoken.CreateToken(securityTokenDescriptor);

            return token;
        }

        /// <summary>
        /// Receives the claims of token by given token as string.
        /// </summary>
        /// <remarks>
        /// Pay attention, one the token is FAKE the method will throw an exception.
        /// </remarks>
        /// <param name="token"></param>
        /// <returns>IEnumerable of claims for the given token.</returns>
        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            if (string.IsNullOrEmpty(token))
                throw new ArgumentException("Given token is null or empty.");

            TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();
            try
            {
                //ClaimsPrincipal tokenValid = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
                var tokenValid = jsontoken.ValidateToken(token, tokenValidationParameters);
                return tokenValid.ClaimsIdentity.Claims;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        #endregion

        #region Private Methods
        private RsaSecurityKey GetPrivateKeyfromCertificate()
        {
            // create the token signed with private key
            // 1. create private security key to create the token
            var rsaPrivateKey = certificate.GetRSAPrivateKey();
            var privateSecurityKey = new RsaSecurityKey(rsaPrivateKey);

            return privateSecurityKey;
        }

        private RsaSecurityKey GetPublicKeyfromCertificate()
        {
            var rsaPublicKey = certificate.GetRSAPublicKey();
            var publicSecurityKey = new RsaSecurityKey(rsaPublicKey);
            return publicSecurityKey;
        }

        // Validate Token
        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidAudience = "Audience",
                ValidIssuer = "Issuer",
                RequireSignedTokens = true,
                IssuerSigningKey = GetPublicKeyfromCertificate()
            };
        }
        #endregion
    }
}