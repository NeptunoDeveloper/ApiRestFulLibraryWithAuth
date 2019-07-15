using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using PrjWebApi01.Models;
using PrjWebApi01.Models.Repository;
using PrjWebApi01.Models.DTO;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System;
using System.Security.Claims;
using Microsoft.Extensions.Configuration;

namespace PrjWebApi01.Controllers
{
    [Produces("application/json")]
    [Route("api/v1/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        IConfiguration Config;

        public AuthController(IConfiguration configuration)
        {
            Config = configuration; 
        }

        [HttpPost("Login")]
        [AllowAnonymous]
        public IActionResult Login([FromBody]AuthDTO auth)
        {
            /////////////////////////////////////////////
            //Código para Validar si usuario es correcto.
            /////////////////////////////////////////////
            
            JwtSecurityToken token;
            DateTime expiration;
            
            //Obtener la llave del archivo appsettings.json
            var llave = Encoding.UTF8.GetBytes(Config["Tokens:Key"]);
            //Crear la llave simetrica: introducir la clave secreta que fue utilizada para firmar digitalmente el token
            var key = new SymmetricSecurityKey(llave);
            var creds = new SigningCredentials(key,SecurityAlgorithms.HmacSha256);

            // Creamos los claims (pertenencias, características) del usuario
            var claims = new Claim[]{
              new Claim(ClaimTypes.Sid, auth.Guid),
              new Claim(ClaimTypes.Role, auth.Role),
              new Claim("Organization",auth.Organization)
            };
            token = new JwtSecurityToken(Config["Tokens:Issuer"],
                                         Config["Tokens:Issuer"],
                                         claims,
                                         expires: DateTime.Now.AddDays(1),
                                         signingCredentials: creds);

            string tokenHandler = new JwtSecurityTokenHandler().WriteToken(token);
            expiration = token.ValidTo;
            return Ok(tokenHandler);
        }
    }
}