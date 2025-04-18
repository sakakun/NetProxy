using System;
using System.Threading.Tasks;
using System.Xml;
using IniParser.Model;
using Newtonsoft.Json;
using Formatting = Newtonsoft.Json.Formatting;

namespace NetProxy
{
    internal class Program
    {
        public static IniData dataSettings { get; set; }
        
        public static async Task Main(string[] args)
        {
            // Validate Configuration
            dataSettings = Configuration.GetIniData();
            
            // Create an instance of the NetLimiterMain class
            var netLimiter = new MainClient();

            // Call the RunAsync method
            await netLimiter.RunAsync();
            
        }
        
    }
}