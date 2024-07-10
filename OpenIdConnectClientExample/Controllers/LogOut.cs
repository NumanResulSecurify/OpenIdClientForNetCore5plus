using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using OpenIdConnectClientExample.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace OpenIdConnectClientExample.Controllers
{
    public class LogOut : Controller
    {
        private readonly IConfiguration _configuration;

        public LogOut(IConfiguration configuration)
        {
            _configuration = configuration;

        }

        // Action to handle post-logout redirection
        public IActionResult SignedOut()
        {
            if (User.Identity.IsAuthenticated)
            {
                // Not logged out yet, retry or handle accordingly
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            // Redirect to homepage or login page as appropriate
            return RedirectToAction(nameof(HomeController.Index), "Home");
        }

      

       /*
        [HttpGet]
        public async Task<IActionResult> FrontChannelLogout(string sid)
        {
            if (User.Identity.IsAuthenticated && User.Claims.Any(c => c.Type == "sid" && c.Value == sid))
            {
                await HttpContext.SignOutAsync(); // Signs out the user from the local session
            }

            return NoContent(); // Or return a view confirming the logout
        }
       */

      
        /*
        public async Task<IActionResult> Logout()
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


            return RedirectToAction("Index", "Home");
        
        }
        */

        [HttpGet]
        public async Task<IActionResult> FrontChannelLogout(string sid)
        {
            if (User.Identity.IsAuthenticated && User.Claims.Any(c => c.Type == "sid" && c.Value == sid))
            {
                await HttpContext.SignOutAsync(); // Signs out the user from the local session
            }

            return NoContent(); // Or return a view confirming the logout
        }

        public async Task<IActionResult> Logout()
        {
            // Triggering local application logout
            await HttpContext.SignOutAsync("Cookies"); // Local session logout
            await HttpContext.SignOutAsync("oidc"); // OIDC logout

            // Assuming you have a way to get all clients that need to be notified
            //var clients = GetClientsNeedingFrontChannelLogout();
            var clients = "crmodic";

            var model = new FrontChannelLogoutViewModel { IframeUrls = new List<string> { "https://192.168.5.36:4443/Account/Logout/" } };

            //var model = new FrontChannelLogoutViewModel { IframeUrls = clients.Select(c => c.FrontChannelLogoutUri).ToList() };

            return View("FrontChannelLogout", model); // View that contains iframes for all clients
        
        }


    }

}
