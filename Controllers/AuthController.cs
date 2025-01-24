using AuthAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthAPI.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        private static List<User> users = new List<User>
        {
            new User { Username = "admin", Password = "12345" },
            new User { Username = "teste", Password = "123456" }
        };

        [HttpPost("login")]
        public ActionResult<UserToken> Login([FromBody] User userLogin)
        {
            try
            {
                var user = users.SingleOrDefault(u => u.Username == userLogin.Username && u.Password == userLogin.Password);

                if (user == null || userLogin == null)
                {
                    return Unauthorized(new { Message = "Invalid username or password!" });
                }

                return Ok(new { Message = BuildToken(userLogin) });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        private UserToken BuildToken(User user)
        {
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiration = DateTime.UtcNow.AddHours(1);
            JwtSecurityToken token = new JwtSecurityToken(
               issuer: null,
               audience: null,
               claims: claims,
               expires: expiration,
               signingCredentials: creds);
            return new UserToken()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = expiration
            };
        }
    }
}
