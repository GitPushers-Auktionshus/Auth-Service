using System;
using AuthServiceAPI.Model;
using Microsoft.AspNetCore.Mvc;

namespace AuthServiceAPI.Service
{
	public interface IAuthenticationRepository
	{
		public Task<string> LoginUser(UserDTO userDTO);

		public string GenerateJwtTokenToUser(string username);

    }
}

