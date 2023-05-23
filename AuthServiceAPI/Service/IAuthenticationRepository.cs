using System;
using AuthServiceAPI.Model;
using Microsoft.AspNetCore.Mvc;

namespace AuthServiceAPI.Service
{
	public interface IAuthenticationRepository
	{
		/// <summary>
		/// Loging in the user and checking with the database, if the password is correct.
		/// </summary>
		/// <param name="userDTO"></param>
		/// <returns>A JWT-token that the user can use to acces endpoints across services</returns>
		public Task<string> LoginUser(UserDTO userDTO);

		/// <summary>
		/// Generates a JWT token using an issuer and a secret. Also includes a username in the token. 
		/// </summary>
		/// <param name="username"></param>
		/// <returns>A JWT-token</returns>
		public string GenerateJwtTokenToUser(string username);

    }
}

