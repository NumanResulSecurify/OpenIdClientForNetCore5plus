using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using IHostingEnvironment = Microsoft.Extensions.Hosting.IHostingEnvironment;

namespace OpenIdConnectClientExample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc(opt => opt.RequireHttpsPermanent = false);
            services.AddControllersWithViews();


            services.AddAuthentication(options =>
            {
                options.DefaultScheme = "numan";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("numan")
            .AddOpenIdConnect("oidc", options =>
            {
                options.SignInScheme = "numan";
                options.Authority = "https://192.168.5.36:4443";
                //options.ClientId = "crmoidc";
                //options.ClientSecret = "0fbb3ca5-3fa1-4812-9b96-676b7e251fd1";

                options.ClientId = "crmoidc";
                options.ClientSecret = "0fbb3ca5-3fa1-4812-9b96-676b7e251fd1";

                options.ResponseType = "code";
                options.ResponseMode = "query";
                options.SaveTokens = true;

                options.SignedOutRedirectUri = "/Logout/SignedOut";
                options.SignOutScheme = "numan"; // Ensure this matches your cookie scheme name
                                                 // Other OIDC configurations
                options.Scope.Clear(); // Clear existing scopes
                options.Scope.Add("openid"); // Required
                //options.Scope.Add("profile"); // Optional
                options.Scope.Add("email"); // Optional
                options.Scope.Add("securify"); // Optional

                options.MetadataAddress = "https://192.168.5.36:4443/.well-known/openid-configuration";
                
                options.MetadataAddress = "https://192.168.5.36:4443/.well-known/openid-configuration";

                options.Configuration = new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration
                {
                    JwksUri = "https://192.168.5.36:4443/.well-known/openid-configuration/jwks",
                    Issuer = "http://securify-adminconsole:60000",
                    AuthorizationEndpoint = "https://192.168.5.36:4443/connect/authorize",
                    TokenEndpoint = "https://192.168.5.36:4443/connect/token",
                    UserInfoEndpoint = "https://192.168.5.36:4443/connect/userinfo",
                    EndSessionEndpoint = "https://192.168.5.36:4443/connect/endsession",
                    CheckSessionIframe = "https://192.168.5.36:4443/connect/checksession",
                    IntrospectionEndpoint = "https://192.168.5.36:4443/connect/introspect",
                };
                
                options.Events = new OpenIdConnectEvents
                {
                    OnSignedOutCallbackRedirect = context =>
                    {
                        context.Response.Redirect("https://localhost:5003/"); // Homepage or desired redirect URI
                        context.HandleResponse(); // Prevent further processing of the request
                        return Task.CompletedTask;
                    }
                };


                services.AddAuthorization(options =>
                {
                    options.AddPolicy("AdminOnly", policy =>
                        policy.RequireAssertion(context =>
                            context.User.Claims.Any(c =>
                                c.Type == "groups" && c.Value.Split(',').Contains("admin"))));
                });


                if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                {
                    options.BackchannelHttpHandler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
                    };
                }

                // Set the TokenValidationParameters to bypass signature validation
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = false,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    SignatureValidator = delegate (string token, TokenValidationParameters parameters)
                    {
                        var jwt = new JwtSecurityToken(token);
                        return jwt;
                    },
                };
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            IdentityModelEventSource.ShowPII = true;

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
