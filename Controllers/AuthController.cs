using AuthAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace AuthAPI.Controllers
{
    [ApiController]
    [Route("/api/v1/auth/")]
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
                if (userLogin == null)
                {
                    return BadRequest(new { Message = "Login data cannot be null." });
                }

                var user = users.FirstOrDefault(u => u.Username == userLogin.Username && u.Password == userLogin.Password);

                if (user == null)
                {
                    return Unauthorized(new { Message = "Invalid username or password!" });
                }

                var userToken = BuildToken(user);

                return Ok(new { Message = "Login successfull!" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpPost("register")]
        public ActionResult<User> Register([FromBody] User userRegister)
        {
            try
            {
                if (userRegister == null)
                {
                    return BadRequest(new { Message = "Register data cannot be null." });
                }

                users.Add(userRegister);

                return Ok(userRegister);
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        [HttpGet("users")]
        public ActionResult<List<User>> Users()
        {
            try
            {
                if (users == null)
                {
                    return NotFound(new { Message = "No users found." });
                }

                return Ok(users);
            } catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        private UserToken BuildToken(User user)
        {
            var jwtKey = _configuration["JWT:key"];
            if (jwtKey == null)
            {
                Console.WriteLine("Set JWT Key on appsettings.");
            }

            // JWT Parts
            var claims = new[] {
                new Claim(JwtRegisteredClaimNames.UniqueName, user.Username),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
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
