using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using OpenIdConnectClientExample.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIdConnectClientExample.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }
        [Authorize]
        public async Task<IActionResult> Index()
        {
            // Token içeriğine erişim
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            var idToken = await HttpContext.GetTokenAsync("id_token");

            // Token içeriğini işleme
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadToken(accessToken) as JwtSecurityToken;

            // JSON içindeki claim'lere erişim
            // var nameClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "name")?.Value;
            var emailClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value;

            // Claim'leri kullanma
            // Örneğin, bu claim'leri bir view'e aktarabilir veya iş mantığınızda kullanabilirsiniz
            //ViewBag["Name"] = nameClaim;

            ViewBag.Email = emailClaim.ToString();

            // Initialize 'groups' outside of the try-catch block
            List<string> groups = new List<string>(); // Initialized as empty list

            // Collect all 'groups' claims
            var groupsClaims = jsonToken.Claims.Where(c => c.Type == "groups").ToList();

            foreach (var claim in groupsClaims)
            {
                // Since each claim's value is a single group name string, add it directly to the list
                groups.Add(claim.Value);
            }

            // Example: Checking if the user is an admin by seeing if they belong to the "Administrators" group
            bool isAuthorized = groups.Contains("crm-admin") || groups.Contains("crm-user");

            bool isAdmin = groups.Contains("crm-admin");

            // Claim'leri ve admin bilgisini bir view'e aktarabiliriz

            ViewBag.IsAdmin = isAdmin;

            //var groups = User.Claims.FirstOrDefault(c => c.Type == "groups")?.Value;
            if (isAuthorized)
            {
                if (isAdmin)
                {
                    ViewBag.Message = "You are ADMIN. You can see this administrative data.";
                }
                else
                {
                    ViewBag.Message = "You are USER. You can only see normal user data.";
                }
            } else
            {
                ViewBag.Message = "<span class='error'>ERROR: YOU ARE NOT AUTHORIZED TO ACCESS THIS APPLICATION!!!</span>";
            }
        

            var model = new FrontChannelLogoutViewModel
            {
                IframeUrls = new List<string> { "https://localhost:5003/Home/logout/" }
            };

            return View(model);
        }
        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
        [Authorize]
        public async Task Logout()
        {
          
            await HttpContext.SignOutAsync("numan"); // Use the registered cookie scheme
            //await HttpContext.SignOutAsync("OnlineBankamatikCookie"); // Use the registered cookie scheme
            //await HttpContext.SignOutAsync("oidc"); // Sign out from OIDC provider

            // Then, sign out of the OpenID Connect session
            await HttpContext.SignOutAsync("oidc", new AuthenticationProperties
            {
                // Redirect to the home page after logout
                RedirectUri = Url.Action("Index", "Home")
            });


        }

        [HttpGet]
        public async Task<IActionResult> FrontLogout()
        {
            // Triggering local application logout
            await HttpContext.SignOutAsync("Cookies"); // Local session logout
            await HttpContext.SignOutAsync("oidc"); // OIDC logout

            // Assuming you have a way to get all clients that need to be notified
            //var clients = GetClientsNeedingFrontChannelLogout();
            var clients = "crmodic";

            var model = new FrontChannelLogoutViewModel();

            model.IframeUrls = new List<string> { "https://localhost:5003/Home/logout/" };

            
            //var model = new FrontChannelLogoutViewModel { IframeUrls = clients.Select(c => c.FrontChannelLogoutUri).ToList() };

            //return View("FrontChannelLogout", model); // View that contains iframes for all clients
            return View(model); // View that contains iframes for all clients
        }

        private bool ValidateLogoutToken(string token)
        {
            // You should implement actual validation here using your JWT library of choice, e.g., Microsoft.IdentityModel.Tokens
            return true; // Placeholder for compilation
        }

        [HttpPost]
        public async Task<IActionResult> BackchannelLogout()
        {
            var logoutToken = await HttpContext.Request.ReadFormAsync();
            var token = logoutToken["logout_token"].FirstOrDefault();

            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("Logout token is required.");
            }

            // Token validation logic here
            if (!ValidateLogoutToken(token))
            {
                return BadRequest("Invalid logout token.");
            }

            // Terminate session or do additional housekeeping
            await HttpContext.SignOutAsync(); // Adjust as necessary for your scheme

            return Ok();
        }
    }
}