using Microsoft.AspNetCore.Authorization;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ToKo.Policy
{
    public class PageAccessRequirement : IAuthorizationRequirement
    {
    }

    public class TimeSpendHandler : AuthorizationHandler<PageAccessRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PageAccessRequirement requirement)
        {
            if (!context.User.HasClaim(c => c.Type == "DateOfJoining"))
            {
                return Task.FromResult(0);
            }

            var dateOfJoining = Convert.ToDateTime(context.User.FindFirst(c => c.Type == "DateOfJoining").Value);

            double calculatedTimeSpend = (DateTime.Now.Date - dateOfJoining.Date).TotalDays;

            if (calculatedTimeSpend >= 365)
            {
                context.Succeed(requirement);
            }

            var myContext = context.Resource as Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext;

            if(myContext != null)
            {
                var controllerName = ((Microsoft.AspNetCore.Mvc.Controllers.ControllerActionDescriptor)myContext.ActionDescriptor).ControllerName;
            }

            return Task.FromResult(0);
        }

        public class RoleCheckerHandler : AuthorizationHandler<PageAccessRequirement>
        {
            protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PageAccessRequirement requirement)
            {
                if(!context.User.HasClaim(c => c.Type == "IsAgent"))
                {
                    return Task.FromResult(0);
                }

                var isAgent = Convert.ToBoolean(context.User.FindFirst(c => c.Type == "IsAgent").Value);

                if (isAgent)
                {
                    context.Succeed(requirement);
                }

                return Task.FromResult(0);
            }
        }
    }
}
