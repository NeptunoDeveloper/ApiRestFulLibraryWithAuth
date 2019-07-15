using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PrjWebApi01.Models;
using PrjWebApi01.Models.DTO;
using PrjWebApi01.Models.DataManager;
using PrjWebApi01.Models.Repository;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace PrjWebApi01
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
            services.AddDbContext<LibraryContext>(options => options.UseNpgsql(Configuration.GetConnectionString("DefaultConnection")));
            services.AddScoped<IDataRepository<Authors,AuthorsDTO>, AuthorsDataManager>();
            services.AddSingleton<IConfiguration>(Configuration);
            services.AddMvc()
                .AddJsonOptions(
                    options => options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore
                ).SetCompatibilityVersion(CompatibilityVersion.Version_2_2);

            AppDomain.CurrentDomain.GetAssemblies();

            //Seguridad
            services.AddAuthentication
                (c =>
                     {
                         c.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                         c.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                     }
                ).AddJwtBearer
                (cfg =>
                    {
                        //cfg.Audience = Configuration["Tokens:Issuer"];
                        //cfg.Authority = Configuration["Tokens:Issuer"];
                        cfg.RequireHttpsMetadata = false;
                        cfg.SaveToken = true;
                        cfg.TokenValidationParameters = new TokenValidationParameters()
                        {
                            ValidateIssuer = false,
                            ValidateAudience = false,
                            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["Tokens:Key"]))
                        };
                    }
                 );
                    

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseAuthentication(); //Seguridad
            app.UseMvc();
        }
    }
}
