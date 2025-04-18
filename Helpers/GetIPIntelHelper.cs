using System;
using System.Data.SQLite;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using IPAddress = CoreLib.Net.IPAddress;

namespace NetProxy
{
    public class GetIPIntelHelper
    {
        private static string GetIPIntelApiKey { get; set; } // Replace with your GetIPIntel API key
        private const string DatabaseFile = "GetIPIntelCache.db";

        public GetIPIntelHelper()
        {
            InitializeDatabase();
            GetIPIntelApiKey = Program.dataSettings["Proxy-Checking"]["api_key"];
        }

        private void InitializeDatabase()
        {
            if (!File.Exists(DatabaseFile))
            {
                SQLiteConnection.CreateFile(DatabaseFile);
            }

            using (var connection = new SQLiteConnection($"Data Source={DatabaseFile};Version=3;"))
            {
                connection.Open();
                string createTableQuery = @"
                CREATE TABLE IF NOT EXISTS Cache (
                    IPAddress TEXT PRIMARY KEY,
                    IsVpn INTEGER,
                    Country TEXT,
                    LastChecked TEXT
                )";
                using (var command = new SQLiteCommand(createTableQuery, connection))
                {
                    command.ExecuteNonQuery();
                }
            }
        }

        public async Task<(bool IsVpn, string Country)> IsVpnIp(IPAddress ip)
        {
            string ipString = ip.ToString();

            // Check the cache
            using (var connection = new SQLiteConnection($"Data Source={DatabaseFile};Version=3;"))
            {
                connection.Open();
                string selectQuery = "SELECT IsVpn, Country, LastChecked FROM Cache WHERE IPAddress = @IPAddress";
                using (var command = new SQLiteCommand(selectQuery, connection))
                {
                    command.Parameters.AddWithValue("@IPAddress", ipString);
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            bool isVpn = reader.GetInt32(0) == 1;
                            string country = reader.GetString(1);
                            DateTime lastChecked = DateTime.Parse(reader.GetString(2));

                            // Return cached result if within 30 days
                            if ((DateTime.UtcNow - lastChecked).TotalDays <= 30)
                            {
                                return (isVpn, country);
                            }
                        }
                    }
                }
            }

            // Call the GetIPIntel API if not in cache or outdated
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    string url = $"https://check.getipintel.net/check.php?ip={ipString}&contact={GetIPIntelApiKey}&format=json";
                    HttpResponseMessage response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();

                    string responseBody = await response.Content.ReadAsStringAsync();
                    JObject jsonResponse = JObject.Parse(responseBody);

                    bool isVpn = jsonResponse["result"]?.ToObject<double>() > 0.99; // Threshold for VPN/proxy detection
                    string country = "Unknown"; // GetIPIntel does not provide country information

                    // Update the cache
                    using (var connection = new SQLiteConnection($"Data Source={DatabaseFile};Version=3;"))
                    {
                        connection.Open();
                        string insertOrUpdateQuery = @"
                        INSERT INTO Cache (IPAddress, IsVpn, Country, LastChecked)
                        VALUES (@IPAddress, @IsVpn, @Country, @LastChecked)
                        ON CONFLICT(IPAddress) DO UPDATE SET
                            IsVpn = excluded.IsVpn,
                            Country = excluded.Country,
                            LastChecked = excluded.LastChecked";
                        using (var command = new SQLiteCommand(insertOrUpdateQuery, connection))
                        {
                            command.Parameters.AddWithValue("@IPAddress", ipString);
                            command.Parameters.AddWithValue("@IsVpn", isVpn ? 1 : 0);
                            command.Parameters.AddWithValue("@Country", country);
                            command.Parameters.AddWithValue("@LastChecked", DateTime.UtcNow.ToString("o"));
                            command.ExecuteNonQuery();
                        }
                    }

                    return (isVpn, country);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error checking IP: {ex.Message}");
                    return (false, "Unknown");
                }
            }
        }
    }
}