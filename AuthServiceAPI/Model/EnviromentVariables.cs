using System;
namespace AuthServiceAPI.Model
{
	// A class used to keep and store the enviroment variables retrieved from the vault.
	public class EnviromentVariables
	{
		public Dictionary<string, string> dictionary { get; set; }

		public EnviromentVariables()
		{
		}
	}
}

