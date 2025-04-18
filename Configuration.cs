using System;
using System.IO;
using IniParser;
using IniParser.Model;
using IniParser.Parser;

namespace NetProxy
{
    public static class Configuration
    {
        private static readonly string ConfigFilePath = "settings.ini";
        private static readonly IniData ParsedData;

        static Configuration()
        {
            if (!File.Exists(ConfigFilePath))
            {
                throw new FileNotFoundException($"Configuration file '{ConfigFilePath}' not found.");
            }

            var parser = new FileIniDataParser(new IniDataParser
            {
                Configuration = { CommentString = "#" } // Allow '#' as a comment character
            });

            ParsedData = parser.ReadFile(ConfigFilePath);
        }
        
        public static IniData GetIniData()
        {
            return ParsedData;
        }
        
    }
    
    
}