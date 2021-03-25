using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using API.Entities;
using API.Interfaces;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace API.Services
{
    public class TokenService : ITokenService
    {
        private readonly SymmetricSecurityKey _key;
        public TokenService(IConfiguration config)
        {
            _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["TokenKey"]));
        }

        public string CreateToken(AppUser user)
        {
            //describe claims: I claim to have {NameId} and {UserName}
            var claims = new List<Claim> {
                new Claim(JwtRegisteredClaimNames.NameId, user.UserName)
            };

            //we're signing the credentials using {_key} with a {HmacSha512Signature} algorithm (encryption)
            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha512Signature);

            //add descriprion of token properties: {Subject} -> Who we are, {Expires} -> When the token will expire,
            //{SigningCredentials} -> Signature ensuring we are who we claim to be
            var tokenDescriptor = new SecurityTokenDescriptor {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.Now.AddDays(7),
                SigningCredentials = creds
            };

            //handler for JWT tokens
            var tokenHandler = new JwtSecurityTokenHandler();

            //finally, the actual token we want
            var token = tokenHandler.CreateToken(tokenDescriptor);

            return tokenHandler.WriteToken(token);
        }
    }
}