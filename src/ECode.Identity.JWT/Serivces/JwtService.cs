namespace ECode.Identity.JWT.Serivces;

using Microsoft.IdentityModel.Tokens;
using ECode.Identity.JWT.Models;
using ECode.Identity.JWT.Options;
using System.Security.Claims;
using System.Text.Json;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using ECode.Identity.JWT.Serivces.Base;

public class JwtService : IJwtService {
    private readonly JwtOption options;

    public JwtService(JwtOption options) => this.options = options;



    public string Create(IEnumerable<Claim>? claims = null)
    {
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



    public DefaultToken Parse(string jwt) {
        var tokenObj = Parse<DefaultToken>(jwt);
        tokenObj.PayloadJson = GetPayload(jwt);

        return tokenObj;
    }



    public TTokent Parse<TTokent>(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt, nameof(jwt));

        var decodedPayload = GetPayload(jwt);

        return JsonSerializer.Deserialize<TTokent>(decodedPayload)!;
    }



    private string GetPayload(string jwt)
    {
        ArgumentNullException.ThrowIfNull(jwt, nameof(jwt));

        var tokenParts = jwt.Split('.', StringSplitOptions.RemoveEmptyEntries);

        if (tokenParts.Length != 3)
        {
            throw new FormatException($"Token format is invalid. JWT: '{jwt}'");
        }

        // get payload part of token
        var payloadBase64 = tokenParts[1];
        payloadBase64 = payloadBase64.PadRight(payloadBase64.Length + payloadBase64.Length * 3 % 4, '=');

        var payloadInBytes = Convert.FromBase64String(payloadBase64);

        // decode payload part into utf-8
        return Encoding.UTF8.GetString(payloadInBytes);
    }
}