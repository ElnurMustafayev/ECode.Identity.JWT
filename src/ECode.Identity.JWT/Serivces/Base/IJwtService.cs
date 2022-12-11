namespace ECode.Identity.JWT.Serivces.Base;

using System.Security.Claims;

public interface IJwtService {
    public string Create(IEnumerable<Claim>? claims = null);
}