using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IdentityCookie.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        [HttpGet]
        public ActionResult Login(string name, string pwd)
        {
            //下面的变量claims是Claim类型的数组，Claim是string类型的键值对，所以claims数组中可以存储任意个和用户有关的信息，
            //不过要注意这些信息都是加密后存储在客户端浏览器cookie中的，所以最好不要存储太多特别敏感的信息，这里我们只存储了用户名到claims数组,
            //表示当前登录的用户是谁
            //var claims = new[] { new Claim("username", username) };
            var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);

            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, pwd));
            identity.AddClaim(new Claim(ClaimTypes.Name, name));
            /*详细类型代表请查阅
             https://docs.microsoft.com/zh-cn/dotnet/api/system.security.claims.claimtypes?redirectedfrom=MSDN&view=netframework-4.8
             */
            ClaimsPrincipal principal = new ClaimsPrincipal(identity);
            Task.Run(async () =>
            {
                    //登录用户，相当于ASP.NET中的FormsAuthentication.SetAuthCookie
                    //await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, user);

                    //可以使用HttpContext.SignInAsync方法的重载来定义持久化cookie存储用户认证信息，例如下面的代码就定义了用户登录后60分钟内cookie都会保留在客户端计算机硬盘上，
                    //即便用户关闭了浏览器，60分钟内再次访问站点仍然是处于登录状态，除非调用Logout方法注销登录。
                    //注意其中的AllowRefresh属性，如果AllowRefresh为true，表示如果用户登录后在超过50%的ExpiresUtc时间间隔内又访问了站点，就延长用户的登录时间（其实就是延长cookie在客户端计算机硬盘上的保留时间），
                    //例如本例中我们下面设置了ExpiresUtc属性为60分钟后，那么当用户登录后在大于30分钟且小于60分钟内访问了站点，那么就将用户登录状态再延长到当前时间后的60分钟。但是用户在登录后的30分钟内访问站点是不会延长登录时间的，
                    //因为ASP.NET Core有个硬性要求，是用户在超过50%的ExpiresUtc时间间隔内又访问了站点，才延长用户的登录时间。
                    //如果AllowRefresh为false，表示用户登录后60分钟内不管有没有访问站点，只要60分钟到了，立马就处于非登录状态（不延长cookie在客户端计算机硬盘上的保留时间，60分钟到了客户端计算机就自动删除cookie）
                    await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,//这里要注意的是HttpContext.SignInAsync(AuthenticationType,…) 所设置的Scheme一定要与前面的配置一样，这样对应的登录授权才会生效。
                principal,
                new AuthenticationProperties()
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddSeconds(30),//有效时间
                    AllowRefresh = true
                });
            }).Wait();
            return Ok();
        }
        /// <summary>
        /// 删除指定的cookie
        /// </summary>
        /// <param name="key">键</param>
        [HttpGet]
        public ActionResult Delete(string key)
        {
            HttpContext.SignOutAsync().Wait();
            return Ok();
        }

        /// <summary>
        /// 获取cookies
        /// </summary>
        /// <param name="key">键</param>
        /// <returns>返回对应的值</returns>
        [HttpGet]
        public ActionResult<string> GetCookies(string key)
        {
            /*使用Ajax请求验证身份
             var token="";
             //登录获取Token
             var settings = {
		       "url": "https://localhost:44364/api/account/login?name=admin&pwd=123456",
		       "method": "GET",
		       "timeout": 0,
		     };
             //使用Token请求Authorize接口
             $.ajax(settings).done(function (response) {
              console.log(response);
              token=response.token;//赋值
              var settings = {
                "url": "https://localhost:44364/api/account/GetCookies?key=name",
                "method": "GET",
                "timeout": 0,
                "headers": {
                  "Authorization":"Bearer "+token,
                },
              };
              $.ajax(settings).done(function (response) {
                console.log(response);
              });
            });
            */
            bool IsAuthenticated = false;
            var requestURL = HttpContext.Request.Path;
            var claims = HttpContext.User.Claims;
            //如果HttpContext.User.Identity.IsAuthenticated为true，
            //或者HttpContext.User.Claims.Count()大于0表示用户已经登录
            if (HttpContext.User.Identity.IsAuthenticated)
            {
                IsAuthenticated = true;
            }


            if (IsAuthenticated)
            {
                //这里通过 HttpContext.User.Claims 可以将我们在Login这个Action中存储到cookie中的所有
                //claims键值对都读出来，比如我们刚才定义的UserName的值admin就在这里读取出来了
                var userName = HttpContext.User.FindFirst(ClaimTypes.Name).Value;

            }
            return requestURL.Value;
        }
    }
}