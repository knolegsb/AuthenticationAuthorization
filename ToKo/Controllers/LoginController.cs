using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using ToKo.Data;
using ToKo.Models;
using ToKo.ViewModels;

namespace ToKo.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    public class LoginController : Controller
    {
        private readonly IConfiguration _config;
        private readonly ApplicationDbContext _context;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signinManager;
        
        public LoginController(IConfiguration config, ApplicationDbContext context, UserManager<AppUser> userManager, SignInManager<AppUser> signinManager)
        {
            _config = config;
            _context = context;
            _userManager = userManager;
            _signinManager = signinManager;
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Login([FromBody]LoginViewModel login)
        {
            IActionResult response = Unauthorized();
            var result = AuthenticateUser(login);


            return View();
        }

        private async Task<AppUser> AuthenticateUser(LoginViewModel login)
        {
            //byte[] hashedPassword;

            //using(var hmac = new System.Security.Cryptography.HMACSHA512)
            //{
            //    hashedPassword = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(login.Password));
            //}

            var user = await _userManager.FindByNameAsync(login.UserName);
            var result = await _signinManager.CheckPasswordSignInAsync(user, login.Password, false);


            if (result.Succeeded)
            {
                return null;
            }

            return null;
        }
    }
}