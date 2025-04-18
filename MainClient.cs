using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security;
using System.Threading.Tasks;
using NetLimiter.Service;
using NetProxy.Helpers;
using IPAddress = CoreLib.Net.IPAddress;

namespace NetProxy
{
    public class MainClient
    {
        private static readonly HashSet<string> WhitelistedIps = InitializeWhitelist();
        private static readonly ConcurrentDictionary<string, int> ConnectionCounts = new ConcurrentDictionary<string, int>();
        
        public async Task RunAsync()
        {
            SecureString securePassword = CreateSecurePassword(Program.dataSettings["Settings"]["pass"]);
            ushort port = ushort.Parse(Program.dataSettings["Settings"]["port"]);
            int connectionLimit = int.Parse(Program.dataSettings["Settings"]["connectionLimit"]);

            using (NLClient client = new NLClient())
            {
                string host = Program.dataSettings["Settings"]["host"];
                if (host == "localhost" || host == "127.0.0.1")
                {
                    try
                    {
                        client.Connect();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to connect to localhost: {ex.Message}");
                        return;
                    }
                }
                else
                {
                    if (!await TryConnectAsync(client, host, port, Program.dataSettings["Settings"]["user"], securePassword))
                    {
                        Console.WriteLine("Failed to connect after multiple attempts.");
                        return;
                    }
                }

                while (true)
                {


                    NodeLoader nodeLoader = client.CreateNodeLoader();
                    nodeLoader.SelectAllNodes();
                    nodeLoader.Load();

                    var cnnLogEvents = nodeLoader.Connections.Nodes
                        .Where(node => node.Parent?.Parent?.AppId?.Path != null &&
                                       node.Parent.Parent.AppId.Path.EndsWith(Program.dataSettings["Settings"]["processName"], StringComparison.OrdinalIgnoreCase))
                        .ToList();

                    ConnectionCounts.Clear();
                    var vpnCheckTasks = new ConcurrentBag<Task>();
                    DisplayHeader(ref cnnLogEvents);
                    
                    foreach (ConnectionNode logEvent in cnnLogEvents)
                    {
                        string ipString = logEvent.RemoteAddress.ToIPAddress4().ToString();
                        
                        // Increment connection count for the IP
                        int currentCount = IncrementConnectionCount(ipString);
                        
                        // Check if the IP is in the whitelist
                        if (WhitelistedIps.Contains(ipString))
                        {
                            string message = $"{ipString,-15} ({ConnectionCounts[ipString]}) - Protected Whitelisted IP Address.";
                            Console.WriteLine(message);
                            continue;
                        }

                        // Check if the connection limit is exceeded
                        if (ConnectionCounts[ipString] > connectionLimit)
                        {
                            string blockMessage = AddVpnBlock(client, logEvent.RemoteAddress);
                            //string blockMessage = "Test";
                            Console.WriteLine($"{ipString,-15} ({ConnectionCounts[ipString]})- Exceeded connection limit. {blockMessage}");
                            continue;
                        }
                        
                        vpnCheckTasks.Add(CheckAndBlockVpnAsync(client, logEvent.RemoteAddress));
                    }
                    
                    // Run all VPN checks in parallel
                    await Task.WhenAll(vpnCheckTasks);

                    Console.WriteLine("=======================================");
                    Console.WriteLine("* - Number of Known Connections Per IP");
                    Console.WriteLine("=======================================");
                    
                    // Wait for the refresh interval
                    await Task.Delay(int.Parse(Program.dataSettings["Settings"]["interval"]));
                }
            }
        }

        private static SecureString CreateSecurePassword(string password)
        {
            SecureString securePassword = new SecureString();
            foreach (char c in password)
            {
                securePassword.AppendChar(c);
            }
            securePassword.MakeReadOnly();
            return securePassword;
        }

        private static async Task<bool> TryConnectAsync(NLClient client, string host, ushort port, string username, SecureString password)
        {
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                try
                {
                    await Task.Run(() => client.Connect(host, port, username, password));
                    return true;
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Connection attempt {attempt} failed: {ex.Message}");
                    if (attempt == 3) return false;
                }
            }
            return false;
        }

        private static void DisplayHeader(ref List<ConnectionNode> cnnLogEvents)
        {
            Console.Clear();
            Console.WriteLine("=======================================");
            Console.WriteLine("Current Connections");
            Console.WriteLine("=======================================");
            Console.WriteLine($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            Console.WriteLine("Active Connections: " + (cnnLogEvents.Count(node => !node.IsClosed)));
            Console.WriteLine("Single IP Connection Limit: " + Program.dataSettings["Settings"]["connectionLimit"]);
            Console.WriteLine("=======================================");
            Console.WriteLine("Remote Address (*) - VPN Status - Country");
            Console.WriteLine("=======================================");
        }

        private static HashSet<string> InitializeWhitelist()
        {
            return new HashSet<string>(
                Program.dataSettings["Whitelist"]
                    .Where(kvp => !string.IsNullOrWhiteSpace(kvp.Value))
                    .Select(kvp => kvp.Value)
            );
        }

        private async Task CheckAndBlockVpnAsync(NLClient client, IPAddress ip)
        {
            string ipString = ip.ToIPAddress4().ToString();

            // Skip whitelisted IPs
            if (WhitelistedIps.Contains(ipString)) return;

            try
            {
                // Perform VPN check
                int proxyService = int.Parse(Program.dataSettings["Proxy-Checking"]["proxyService"]);
                bool isVpn = false;
                string country = "Unknown";

                switch (proxyService)
                {
                    case 1:
                        var proxyCheckHelper = new ProxyCheckHelper();
                        (isVpn, country) = await proxyCheckHelper.IsVpnIp(ip);
                        break;
                    case 2:
                        var ipQualityScoreHelper = new IPQualityScoreHelper();
                        (isVpn, country) = await ipQualityScoreHelper.IsVpnIp(ip);
                        break;
                    case 3:
                        var ip2ProxyHelper = new IP2ProxyHelper();
                        (isVpn, country) = await ip2ProxyHelper.IsVpnIp(ip);
                        break;
                    case 4:
                        var ipHubHelper = new IPHubHelper();
                        (isVpn, country) = await ipHubHelper.IsVpnIp(ip);
                        break;
                    case 5:
                        var fraudLabsProHelper = new FraudLabsProHelper();
                        (isVpn, country) = await fraudLabsProHelper.IsVpnIp(ip);
                        break;
                    case 6:
                        var abuseIpdbHelper = new AbuseIPDBHelper();
                        (isVpn, country) = await abuseIpdbHelper.IsVpnIp(ip);
                        break;
                    case 7:
                        var getIpIntelHelper = new GetIPIntelHelper();
                        (isVpn, country) = await getIpIntelHelper.IsVpnIp(ip);
                        break;
                    case 8:
                        var vpnApIioHelper = new VPNAPIioHelper();
                        (isVpn, country) = await vpnApIioHelper.IsVpnIp(ip);
                        break;
                    case 9:
                        var shodanHelper = new ShodanHelper();
                        (isVpn, country) = await shodanHelper.IsVpnIp(ip);
                        break;
                }
                
                string message = $"{ipString,-15} ({ConnectionCounts[ipString]}) - VPN: {isVpn,-5} - Country: {country}";

                if (isVpn)
                {
                    string blockMessage = AddVpnBlock(client, ip);
                    message += $" - {blockMessage}";
                }

                Console.WriteLine(message);
            }
            finally
            {
                
            }
        }

        private string AddVpnBlock(NLClient client, IPAddress ip)
        {
            var filter = client.Filters.FirstOrDefault(f => f.Name == Program.dataSettings["Settings"]["filterName"]);

            if (filter == null)
            {
                return "Filter not found.";
            }

            var remoteAddressFilter = filter.Functions
                .OfType<FFRemoteAddressInRange>()
                .FirstOrDefault();

            if (remoteAddressFilter == null)
            {
                return "No existing 'Remote address in range' function found.";
            }

            var ipString = ip.ToIPAddress4().ToString();
            if (remoteAddressFilter.Values.Any(range =>
                    IsInRange(range.Range.Start.ToString(), range.Range.End.ToString(), ipString)))
            {
                return $"IP {ipString} is already in the filter range.";
            }

            remoteAddressFilter.Values.Add(new IPRangeFilterValue(ipString, ipString));
            client.UpdateFilter(filter);
            return $"IP {ipString} added to the filter.";
        }

        private static bool IsInRange(string startAddress, string endAddress, string ipAddress)
        {
            var start = System.Net.IPAddress.Parse(startAddress);
            var end = System.Net.IPAddress.Parse(endAddress);
            var ip = System.Net.IPAddress.Parse(ipAddress);

            var startBytes = start.GetAddressBytes();
            var endBytes = end.GetAddressBytes();
            var ipBytes = ip.GetAddressBytes();

            for (int i = 0; i < startBytes.Length; i++)
            {
                if (ipBytes[i] < startBytes[i] || ipBytes[i] > endBytes[i])
                {
                    return false;
                }
            }
            return true;
        }
        
        private int IncrementConnectionCount(string ip)
        {
            return ConnectionCounts.AddOrUpdate(ip, 1, (key, oldValue) => oldValue + 1);
        }
    }
}