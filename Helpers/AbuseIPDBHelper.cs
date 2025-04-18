using System;
        using System.Data.SQLite;
        using System.IO;
        using System.Net.Http;
        using System.Threading.Tasks;
        using Newtonsoft.Json.Linq;
        using IPAddress = CoreLib.Net.IPAddress;
        
        namespace NetProxy
        {
            public class AbuseIPDBHelper
            {
                private static string AbuseIPDBApiKey { get; set; } // Replace with your AbuseIPDB API key
                private const string DatabaseFile = "AbuseIPDBCache.db";
        
                public AbuseIPDBHelper()
                {
                    InitializeDatabase();
                    AbuseIPDBApiKey = Program.dataSettings["Proxy-Checking"]["api_key"];
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
                        string selectQuery = "SELECT IsVpn, LastChecked FROM Cache WHERE IPAddress = @IPAddress";
                        using (var command = new SQLiteCommand(selectQuery, connection))
                        {
                            command.Parameters.AddWithValue("@IPAddress", ipString);
                            using (var reader = command.ExecuteReader())
                            {
                                if (reader.Read())
                                {
                                    bool isVpn = reader.GetInt32(0) == 1;
                                    DateTime lastChecked = DateTime.Parse(reader.GetString(1));
        
                                    // Return cached result if within 30 days
                                    if ((DateTime.UtcNow - lastChecked).TotalDays <= 30)
                                    {
                                        return (isVpn, "Unknown"); // Country is not cached
                                    }
                                }
                            }
                        }
                    }
        
                    // Call the AbuseIPDB API if not in cache or outdated
                    using (HttpClient client = new HttpClient())
                    {
                        try
                        {
                            string url = $"https://api.abuseipdb.com/api/v2/check?ipAddress={ipString}&maxAgeInDays=30";
                            client.DefaultRequestHeaders.Add("Key", AbuseIPDBApiKey);
                            client.DefaultRequestHeaders.Add("Accept", "application/json");
                            HttpResponseMessage response = await client.GetAsync(url);
                            response.EnsureSuccessStatusCode();
        
                            string responseBody = await response.Content.ReadAsStringAsync();
                            JObject jsonResponse = JObject.Parse(responseBody);
        
                            bool isVpn = jsonResponse["data"]?["isPublicProxy"]?.ToObject<bool>() ?? false;
                            string country = jsonResponse["data"]?["countryCode"]?.ToString() ?? "Unknown";
        
                            // Update the cache
                            using (var connection = new SQLiteConnection($"Data Source={DatabaseFile};Version=3;"))
                            {
                                connection.Open();
                                string insertOrUpdateQuery = @"
                                INSERT INTO Cache (IPAddress, IsVpn, LastChecked)
                                VALUES (@IPAddress, @IsVpn, @LastChecked)
                                ON CONFLICT(IPAddress) DO UPDATE SET
                                    IsVpn = excluded.IsVpn,
                                    LastChecked = excluded.LastChecked";
                                using (var command = new SQLiteCommand(insertOrUpdateQuery, connection))
                                {
                                    command.Parameters.AddWithValue("@IPAddress", ipString);
                                    command.Parameters.AddWithValue("@IsVpn", isVpn ? 1 : 0);
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