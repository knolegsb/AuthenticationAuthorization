using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using ToKo.Data;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ToKo.Policy;
using Microsoft.AspNetCore.Authorization;
using static ToKo.Policy.TimeSpendHandler;
using System.Security.Claims;
using Microsoft.AspNetCore.SpaServices.AngularCli;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace ToKo
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<CookiePolicyOptions>(options =>
            {
                // This lambda determines whether user consent for non-essential cookies is needed for a given request.
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = Configuration["Jwt:Issuer"],
                    ValidAudience = Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Jwt:SecretKey"])),
                    ClockSkew = TimeSpan.Zero
                };
                services.AddCors();
            });

            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<IdentityUser, IdentityRole>()
                .AddDefaultUI(UIFramework.Bootstrap4)
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.AddMvc()
                .AddRazorPagesOptions(options =>
                {
                    options.Conventions.AuthorizePage("/test1", "OnlyAdminAccess");
                })
                .SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            services.AddAuthorization(options =>
            {
                options.AddPolicy("OnlyAdminAccess", policy => policy.RequireRole("Admin"));
                options.AddPolicy("IsAdminClaimAccess", policy => policy.RequireClaim("DateOfJoining"));
                options.AddPolicy("IsAdminClaimAccess", policy => policy.RequireClaim("IsAdmin", "true"));
                options.AddPolicy("NonAdminAccess", policy => policy.RequireClaim("IsAdmin", "false"));
                options.AddPolicy("RoleBasedClaim", policy => policy.RequireClaim("ManagerPermissions", "true"));
                options.AddPolicy("Morethan365DaysClaim", policy => policy.Requirements.Add(new MinimumTimeSpendRequirement(365)));
                options.AddPolicy("AccessPageTestMethod5", policy => policy.Requirements.Add(new PageAccessRequirement()));
                options.AddPolicy("AccessPageTestMethod6",
                            policy => policy.RequireAssertion(context =>
                                        context.User.HasClaim(c =>
                                            (c.Type == "IsAgent" && Convert.ToBoolean(context.User.FindFirst(c2 => c2.Type == "IsAgent").Value)) ||
                                            (c.Type == "DateOfJoining" && (DateTime.Now.Date - Convert.ToDateTime(context.User.FindFirst(c2 => c2.Type == "DateOfJoining").Value).Date).TotalDays >= 365))
                                            ));
            });

            services.AddSingleton<IAuthorizationHandler, MinimumTimeSpendHandler>();
            services.AddSingleton<IAuthorizationHandler, TimeSpendHandler>();
            services.AddSingleton<IAuthorizationHandler, RoleCheckerHandler>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, IServiceProvider serviceProvider)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseCookiePolicy();

            app.UseAuthentication();

            if (!env.IsDevelopment())
            {
                app.UseSpaStaticFiles();
            }
            
            //app.UseMvc(routes =>
            //{
            //    routes.MapRoute(
            //        name: "default",
            //        template: "{controller=Home}/{action=Index}/{id?}");
            //});

            CreateRoles(serviceProvider).Wait();

            app.UseSpa(spa =>
            {
                spa.Options.SourcePath = "ClientApp";
                if (env.IsDevelopment())
                {
                    spa.UseAngularCliServer(npmScript: "start");
                }
            });
        }

        private async Task CreateRoles(IServiceProvider serviceProvider)
        {
            var RoleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var UserManager = serviceProvider.GetRequiredService<UserManager<IdentityUser>>();
            string[] roleNames = { "Admin", "User", "Agent" };
            IdentityResult roleResult;

            foreach(var roleName in roleNames)
            {
                var roleExist = await RoleManager.RoleExistsAsync(roleName);
                if (!roleExist)
                {
                    roleResult = await RoleManager.CreateAsync(new IdentityRole(roleName));
                }
            }

            IdentityUser user = await UserManager.FindByEmailAsync("jingle@gmail.com");

            if (user == null)
            {
                user = new IdentityUser()
                {
                    UserName = "jingle@gmail.com",
                    Email = "jingle@gmail.com"
                };
                await UserManager.CreateAsync(user, "Jingle@123");
            }
            await UserManager.AddToRoleAsync(user, "Admin");

            IdentityUser user1 = await UserManager.FindByEmailAsync("bella@gmail.com");
            if (user1 == null)
            {
                user1 = new IdentityUser()
                {
                    UserName = "bella@gmail.com",
                    Email = "bella@gmail.com",
                };
                await UserManager.CreateAsync(user1, "Bella@123");
            }
            await UserManager.AddToRoleAsync(user1, "User");

            IdentityUser user2 = await UserManager.FindByEmailAsync("bondage@gmail.com");

            if (user2 == null)
            {
                user2 = new IdentityUser()
                {
                    UserName = "bondage@gmail.com",
                    Email = "bondage@gmail.com",
                };
                await UserManager.CreateAsync(user2, "Bondage@123");
            }
            await UserManager.AddToRoleAsync(user2, "Agent");

            // Added Roles
            var roleResult2 = await RoleManager.FindByNameAsync("Administrator");
            if (roleResult2 == null)
            {
                roleResult2 = new IdentityRole("Administrator");
                await RoleManager.CreateAsync(roleResult2);
            }

            var roleClaimList = (await RoleManager.GetClaimsAsync(roleResult2)).Select(p => p.Type);
            if (!roleClaimList.Contains("ManagerPermissions"))
            {
                await RoleManager.AddClaimAsync(roleResult2, new System.Security.Claims.Claim("ManagerPermissions", "true"));
            }

            IdentityUser user3 = await UserManager.FindByEmailAsync("goodsean@gmail.com");

            if (user3 == null)
            {
                user3 = new IdentityUser()
                {
                    UserName = "goodsean@gmail.com",
                    Email = "goodsean@gmail.com",
                };
                await UserManager.CreateAsync(user3, "Goodsean@123");
            }

            await UserManager.AddToRoleAsync(user3, "Administrator");

            var claimList = (await UserManager.GetClaimsAsync(user)).Select(p => p.Type);
            if (!claimList.Contains("DateOfJoining"))
            {
                await UserManager.AddClaimAsync(user, new Claim("DateOfJoining", "07/25/1999"));
            }
            if (!claimList.Contains("IsAdmin"))
            {
                await UserManager.AddClaimAsync(user, new Claim("IsAdmin", "true"));
            }

            IdentityUser user4 = await UserManager.FindByEmailAsync("goodsean@gmail.com");

            if (user4 == null)
            {
                user4 = new IdentityUser()
                {
                    UserName = "goodsean@gmail.com",
                    Email = "goodsean@gmail.com",
                };
                await UserManager.CreateAsync(user4, "Goodsean@123");
            }
            var claimList2 = (await UserManager.GetClaimsAsync(user4)).Select(p => p.Type);
            if (!claimList2.Contains("IsAdmin"))
            {
                await UserManager.AddClaimAsync(user4, new Claim("IsAdmin", "false"));
            }
            if (!claimList2.Contains("DateOfJoining"))
            {
                await UserManager.AddClaimAsync(user4, new Claim("DateOfJoining", "09/09/2017"));
            }
            if (!claimList2.Contains("IsAgent"))
            {
                await UserManager.AddClaimAsync(user4, new Claim("IsAgent", "true"));
            }
        }
    }
}
