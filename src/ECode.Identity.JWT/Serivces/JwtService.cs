namespace ECode.Identity.JWT.Serivces;

using Microsoft.IdentityModel.Tokens;
using ECode.Identity.JWT.Options;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using ECode.Identity.JWT.Serivces.Base;
using Microsoft.Extensions.Options;

public class JwtService : IJwtService {
    private readonly JwtOption? options;

    public JwtService(JwtOption options) => this.options = options;

    public JwtService(IOptions<JwtOption> options) => this.options = options.Value;

    public JwtService() { }



    public string Create(IEnumerable<Claim>? claims = null) {
        if(this.options == null)
            throw new Exception($"Set {nameof(JwtOption)} for calling {nameof(Create)} method.");

        var credentials = new SigningCredentials(
            key: new SymmetricSecurityKey(options.EncryptionKeyInBytes),
            algorithm: options.Algorithm
        );

        var token = new JwtSecurityToken(
            audience: nameof(ECode),
            issuer: nameof(Assembly.FullName),
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(options.AccessTokenExpTimeInMinutes),
            signingCredentials: credentials
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}