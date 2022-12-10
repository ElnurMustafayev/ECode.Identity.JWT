using ECode.Identity.JWT.Models;
using System.Security.Claims;

namespace ECode.Identity.JWT.Serivces.Base;

public interface IJwtService {
    public string Create(IEnumerable<Claim>? claims = null);
    public DefaultToken Parse(string jwt);
    public TTokent Parse<TTokent>(string jwt);
}