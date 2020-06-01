using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using AuthenticationService.Managers;
using AuthenticationService.Models;

namespace AuthenticationService
{
    class Program
    {
        static void Main(string[] args)
        {
            IAuthContainerModel model = GetJWTContainerModel("Harsimran Singh", "hsingh@dhcsystems.com.au");
            IAuthService authService = new JWTService(model.SecretKey);

            string token = authService.GenerateToken(model);

            if (!authService.IsTokenValid(token))
                throw new UnauthorizedAccessException();
            else
            {
                Console.WriteLine("JSON :\n" + token);
                Console.WriteLine();
                List<Claim> claims = authService.GetTokenClaims(token).ToList();

                Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.GivenName)).Value);
                Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Email)).Value);
                Console.ReadLine();
            }
        }

        #region Private Methods
        private static JWTContainerModel GetJWTContainerModel(string name, string email)
        {
            return new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.GivenName, name),
                    new Claim(ClaimTypes.Email, email),

                }
            };
        }
        #endregion
    }
}
