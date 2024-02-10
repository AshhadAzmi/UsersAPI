using System.Data;
using AutoMapper;
using Dapper;
using DotnetAPI.Data;
using DotnetAPI.Dtos;
using DotnetAPI.Helpers;
using DotnetAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DotnetAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly DataContextDapper _dapper;
        private readonly AuthHelper _authHelper;
        private readonly ReuseableSql _reuseableSql;
        private readonly IMapper _mapper;

        public AuthController(IConfiguration config)
        {
            _dapper = new DataContextDapper(config);
            _authHelper = new AuthHelper(config);
            _reuseableSql = new ReuseableSql(config);
            _mapper = new Mapper(new MapperConfiguration(cfg =>
            {
                cfg.CreateMap<UserForRegistrationDto, UserComplete>();
            }));
        }

        [AllowAnonymous]
        [HttpPost("Register")]
        public IActionResult Register(UserForRegistrationDto registrationDto)
        {
            if (registrationDto.Password == registrationDto.PasswordConfirm)
            {
                string sqlCheckUserExists = "SELECT Email from TutorialAppSchema.Auth WHERE Email = '" +
                    registrationDto.Email + "'";

                IEnumerable<string> existingUsers = _dapper.LoadData<string>(sqlCheckUserExists);
                if (existingUsers.Count() == 0)
                {
                    UserForLoginDto userForSetPassword = new UserForLoginDto()
                    {
                        Email = registrationDto.Email,
                        Password = registrationDto.Password
                    };

                    if (_authHelper.SetPassword(userForSetPassword))
                    {
                        UserComplete userComplete = _mapper.Map<UserComplete>(registrationDto);
                        userComplete.Active = true;

                        if (_reuseableSql.UpsertUser(userComplete))
                        {
                            return Ok();
                        }
                        throw new Exception("Failed to Add User!");
                    }
                    throw new Exception("Failed to register user!");
                }
                throw new Exception("User Already Exists!");
            }
            throw new Exception("Passwords didn't match!");
        }

        [HttpPut("ResetPassword")]
        public IActionResult ResetPassword(UserForLoginDto userForSetPassword)
        {
            if (_authHelper.SetPassword(userForSetPassword))
            {
                return Ok();
            }
            throw new Exception("Failed to Update Password!");
        }

        [AllowAnonymous]
        [HttpPost("Login")]
        public IActionResult Login(UserForLoginDto loginDto)
        {
            string sqlForHashAndSalt = @"EXEC TutorialAppSchema.spLoginConfirmation_Get 
                @Email = @EmailParam";

            DynamicParameters sqlParameters = new DynamicParameters();

            // SqlParameter emailParameter = new SqlParameter("@EmailParam", SqlDbType.VarChar);
            // emailParameter.Value = loginDto.Email;
            // sqlParameters.Add(emailParameter);

            sqlParameters.Add("@EmailParam", loginDto.Email, DbType.String);

            UserForLoginConfirmationDto userForConfirmation = _dapper
                .LoadDataSingleWithParameters<UserForLoginConfirmationDto>(sqlForHashAndSalt, sqlParameters);

            byte[] passwordHash = _authHelper.GetPasswordHash(loginDto.Password, userForConfirmation.PasswordSalt);

            for (int i = 0; i < passwordHash.Length; i++)
            {
                if (passwordHash[i] != userForConfirmation.PasswordHash[i])
                {
                    return StatusCode(401, "Incorrect Password!");
                }
            }

            string userIdSql = @"
                SELECT UserId FROM TutorialAppSchema.Users WHERE Email = '" +
                loginDto.Email + "'";

            int userId = _dapper.LoadDataSingle<int>(userIdSql);

            return Ok(new Dictionary<string, string> {
                {"token", _authHelper.CreateToken(userId)}
            });
        }

        [HttpGet("RefreshToken")]
        public string RefreshToken()
        {
            string userIdSql = @"
                SELECT UserId FROM TutorialAppSchema.Users WHERE UserId = '" +
                User.FindFirst("userId")?.Value + "'";

            int userId = _dapper.LoadDataSingle<int>(userIdSql);

            return _authHelper.CreateToken(userId);
        }

    }
}