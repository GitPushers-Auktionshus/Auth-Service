using System;
namespace AuthServiceAPI.Model
{
	// A class used to keep and store the enviroment variables retrieved from the vault.
	public class EnvVariables
	{
		public Dictionary<string, string> dictionary { get; set; }

		public EnvVariables()
		{
		}
	}
}

