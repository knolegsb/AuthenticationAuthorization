using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ToKo.Controllers
{
    public class TestController : Controller
    {
        [Authorize(Roles = "Admin")]
        public IActionResult OnlyAdminAccess()
        {
            ViewData["role"] = "Admin";
            return View("MyPage");
        }

        [Authorize(Roles = "User")]
        public IActionResult OnlyUserAccess()
        {
            ViewData["role"] = "User";
            return View("MyPage");
        }
        [Authorize(Roles = "Agent")]
        public IActionResult OnlyAgentAccess()
        {
            ViewData["role"] = "Agent";
            return View("MyPage");
        }

        [Authorize(Policy = "OnlyAdminAccess")]
        public IActionResult PolicyExample()
        {
            ViewData["role"] = "Admin";
            return View("MyPage");
        }

        [Authorize(Roles = "Admin, User")]
        public IActionResult MultipleAccess()
        {
            ViewData["role"] = "Admin & User";
            return View("MyPage");
        }
    }
}