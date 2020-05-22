using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace IdentityCookie
{
    /// <summary>
    /// 实现cookie认证授权校验
    /// 参考地址：https://www.cnblogs.com/OpenCoder/p/8341843.html
    /// </summary>
    public class UserAuthorizeAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {

            var requestURL = context.HttpContext.Request.Path;
            //如果HttpContext.User.Identity.IsAuthenticated为true，
            //或者HttpContext.User.Claims.Count()大于0表示用户已经登录
            if (!requestURL.Value.ToLower().Contains("/login"))
            {
                if (context.HttpContext.User.Identity.IsAuthenticated)
                {
                    //这里通过 HttpContext.User.Claims 可以将我们在Login这个Action中存储到cookie中的所有
                    //claims键值对都读出来，比如我们刚才定义的UserName的值admin就在这里读取出来了
                    var userName = context.HttpContext.User.FindFirstValue(ClaimTypes.Name);
                    //logger.Info($"[{userName}]用户登录校验成功,请求地址[{requestURL}]");
                }
                else
                {
                    //logger.Info($"没登录访问地址[{requestURL}]");
                    context.Result = new JsonResult("没登录访问地址");
                }
            }
            base.OnActionExecuting(context);
        }
    }
}
