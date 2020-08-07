using System;
using System.Globalization;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using TCAdmin.Interfaces.Logging;
using TCAdmin.SDK.Objects;
using TCAdmin.SDK.Web.MVC;
using TCAdmin.SDK.Web.MVC.Controllers;

namespace TCAdminImpersonation.Controllers
{
    public class ImpersonationController : BaseController
    {
        public ActionResult AsUser(int userId)
        {
            var currentUser = TCAdmin.SDK.Session.GetCurrentUser();
            if (currentUser.DemoMode)
            {
                TCAdmin.SDK.LogManager.Write(
                    $"{currentUser.UserName} tried to impersonate but failed due to they are a demo account.",
                    LogType.Information);
                return Redirect(Request.UrlReferrer?.ToString());
            }
            
            var user = new User(userId);
            if (currentUser.UserType == UserType.Admin && user.UserType == UserType.Admin ||
                currentUser.UserType == UserType.SubAdmin && user.UserType == UserType.SubAdmin ||
                currentUser.UserType == UserType.SubAdmin && user.UserType == UserType.Admin)
            {
                TCAdmin.SDK.LogManager.Write(
                    $"{currentUser.UserName} tried to impersonate {user.UserName} but failed due to {currentUser.UserType} > {user.UserType}",
                    LogType.Information);
                return Redirect(Request.UrlReferrer?.ToString());
            }

            var cookie = FormsAuthentication.GetAuthCookie(user.UserId.ToString(), false);
            var cookieData = new FormsAuthenticationCookieData
            {
                ["lastlogdate"] = user.LastLoginUtc.ToString(CultureInfo.InvariantCulture),
                ["lastlogip"] = user.LastLoginIp,
                ["userkey"] = user.CustomFields["__TCA:COOKIE_KEY"].ToString(),
                ["userid"] = user.UserId.ToString()
            };

            var impersonationCookie = new HttpCookie("Impersonation", this.Request.Cookies.Get("__TCAdmin2")?.Value);
            var impersonationUserCookie = new HttpCookie("ImpersonationUser", currentUser.UserId.ToString());
            HttpContext.Response.Cookies.Add(impersonationCookie);
            HttpContext.Response.Cookies.Add(impersonationUserCookie);

            var oldTicket = FormsAuthentication.Decrypt(cookie.Value);
            var newTicket = new FormsAuthenticationTicket(oldTicket.Version, oldTicket.Name, oldTicket.IssueDate,
                oldTicket.Expiration, oldTicket.IsPersistent, cookieData.ToString());
            cookie.Value = FormsAuthentication.Encrypt(newTicket);
            HttpContext.Response.Cookies.Add(cookie);
            
            TCAdmin.SDK.LogManager.Write($"{currentUser.UserName} is now impersonating as {user.UserName}", LogType.Information);

            return Redirect("/");
        }

        public ActionResult Revert()
        {
            var impersonationUserCookie =
                int.Parse(this.HttpContext.Request.Cookies.Get("ImpersonationUser")?.Value ?? "-1");
            if (impersonationUserCookie == -1)
            {
                return Redirect("/");
            }

            var impersonationCookie = this.HttpContext.Request.Cookies.Get("Impersonation")?.Value;
            var cookie = FormsAuthentication.GetAuthCookie(impersonationUserCookie.ToString(), false);
            var impersonationTicket = FormsAuthentication.Decrypt(impersonationCookie);
            var newTicket = new FormsAuthenticationTicket(impersonationTicket.Version, impersonationTicket.Name,
                impersonationTicket.IssueDate, impersonationTicket.Expiration, impersonationTicket.IsPersistent,
                impersonationTicket.UserData);
            cookie.Value = FormsAuthentication.Encrypt(newTicket);
            System.Web.HttpContext.Current.Response.Cookies.Add(cookie);
            RemoveImpersonationCookies();
            
            TCAdmin.SDK.LogManager.Write($"User ID: {impersonationUserCookie} ended impersonation.", LogType.Information);

            return Redirect("/");
        }

        private void RemoveImpersonationCookies()
        {
            // ReSharper disable once PossibleNullReferenceException
            HttpContext.Response.Cookies.Get("Impersonation").Expires = DateTime.Now.AddDays(-1);
            // ReSharper disable once PossibleNullReferenceException
            HttpContext.Response.Cookies.Get("ImpersonationUser").Expires = DateTime.Now.AddDays(-1);
            ;
        }

        public static bool IsImpersonating()
        {
            return System.Web.HttpContext.Current.Request.Cookies["Impersonation"] != null;
        }
    }
}