using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MimeKit;
using MailKit.Net.Smtp;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace EmailComfirmation.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController(UserManager<IdentityUser> userManager) : ControllerBase
    {
        [HttpPost("register/{email}/{password}")]

        public async Task<IActionResult> Register(string email, string password)
        {
            var user = await GetUser(email);
            if (user != null)
                return BadRequest();

            var result = await userManager.CreateAsync(new IdentityUser()
            {
                UserName = email,
                Email = email,
                PasswordHash = password
            }, password);

            if (!result.Succeeded) return BadRequest();

            var _user = await GetUser(email);
            var emailCode = await userManager.GenerateEmailConfirmationTokenAsync(_user!);
            string sendEmail = SendEmail(_user!.Email!, emailCode);
            return Ok(sendEmail);
        }

        private string SendEmail(string email, string emailCode)
        {
            StringBuilder emailMessage = new StringBuilder();
            emailMessage.AppendLine("<html>");
            emailMessage.AppendLine("<body>");
            emailMessage.AppendLine($"<p> Dear {email}, <p>");
            emailMessage.AppendLine("<p> Thank You for registering with us!. Please confirm your email by Entering the following code: </p>");
            emailMessage.AppendLine($"<p> <b> {emailCode} </b> </p>");
            emailMessage.AppendLine("<p> if you did not request this please ignor this email.</p>");
            emailMessage.AppendLine("<p> Thanks.</p>");
            emailMessage.AppendLine("</body>");
            emailMessage.AppendLine("</html>");


            string message = emailMessage.ToString();
            var _email = new MimeMessage();
            _email.To.Add(MailboxAddress.Parse("mae.jacobi@ethereal.email"));
            _email.From.Add(MailboxAddress.Parse("mae.jacobi@ethereal.email"));
            _email.Subject = "Email Confirmation";
            _email.Body = new TextPart("html") { Text = message };

            using var smtp = new SmtpClient();
            smtp.Connect("smtp.ethereal.email", 587, MailKit.Security.SecureSocketOptions.StartTls);
            smtp.Authenticate("mae.jacobi@ethereal.email", "etbc4dndrAC1rAx5zR");
            smtp.Send(_email);
            smtp.Disconnect(true);
            return "Registration succesfull";
        }

        [HttpPost("comfirmation/{email}/{code:int}")]
        public async Task<IActionResult> ComfirmEmail(string email, int code)
        {
            var user = await GetUser(email);
            if (string.IsNullOrEmpty(email) || code <= 0)
                return BadRequest("Code is Invalaid please input the correct code");
            if (user == null)
                return BadRequest("User not found");

            var result = await userManager.ConfirmEmailAsync(user, code.ToString());
            if (!result.Succeeded)
                return BadRequest();

            return Ok("Email Confirmed succesfully, proceed to login");
        }

        [HttpPost("login/{email}/{password}")]
        public async Task<IActionResult> Login(string email, string password)
        {
            var user = await GetUser(email);
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
                return BadRequest("User not found");

            bool isEmailConfirmed = await userManager.IsEmailConfirmedAsync(user!);
            if (!isEmailConfirmed)
                return BadRequest("Please comfirm email before loging ");

            return Ok(new[] { "Login succesfull", GenerateToken(user) });
        }

        private string GenerateToken(IdentityUser? user)
        {
            byte[] key = Encoding.ASCII.GetBytes("AQeetyyuuhb214343nsvdbbnsnfskjdfkjjjru5t588djsbsb");
            var securityKey = new SymmetricSecurityKey(key);
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
            var claims = new[]
            {
               new Claim(JwtRegisteredClaimNames.Sub, user!.Email!),
               new Claim(JwtRegisteredClaimNames.Email, user!.Email!)
            };

            var token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: credentials
            );
            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        //[HttpPost("forgotpassword/{email}")]    
        private async Task<IdentityUser?> GetUser(string email) => await userManager.FindByEmailAsync(email);

        [HttpGet("protected")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public string GetMessage() => "This message is coming from protected endpoint";

    }
}