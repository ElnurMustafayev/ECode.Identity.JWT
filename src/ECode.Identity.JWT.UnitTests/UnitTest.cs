using ECode.Identity.JWT.Helpers;
using ECode.Identity.JWT.Options;
using ECode.Identity.JWT.Serivces;
using ECode.Identity.JWT.Serivces.Base;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace ECode.Identity.JWT.UnitTests;

public class UnitTest
{
    private JwtOption jwtOption;
    private IJwtService jwtService;

    public UnitTest() {
        this.jwtOption = new JwtOption(
            encryptionKey: "45f1d8e7-3fde-4107-885e-0bafe8ef0a2b",
            algorithm: SecurityAlgorithms.HmacSha256Signature,
            accessTokenExpTimeInMinutes: 30
            );

        this.jwtService = new JwtService(this.jwtOption);
    }

    [Fact]
    void SuccessDefaultToken() {
        var jwt = this.jwtService.Create();
        var token = JwtParser.Parse(jwt);

        Assert.True(true);
    }

    [Theory]
    [InlineData("d49350c8-0160-4925-ac3b-939b3e096065")]
    [InlineData("45f1d8e73fde4107885e0bafe8ef0a2b")]
    void SuccessWithClaims(in string id) {
        var claims = new List<Claim>() {
            new Claim(nameof(id), id),
        };

        var claimsJwt = this.jwtService.Create(claims);
        var claimsToken = JwtParser.Parse(claimsJwt);

        Assert.Equal(claimsToken["id"], id);
        Assert.Equal(claimsToken["Id"], claimsToken["ID"]);
    }
}