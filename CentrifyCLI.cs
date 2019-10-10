/**
    Copyright 2019 Centrify Corporation
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
**/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using McMaster.Extensions.CommandLineUtils;

//  Uses:
//      NewtonSoft.JSON
//      MiMaster.Extensions.CommandLineUtils, a fork of Microsoft's discontinued command line utils.
//      ref: https://github.com/natemcmaster/CommandLineUtils
//  Package for native platforms with, e.g., dotnet publish -c Release -r win10-x64
//  List of Runtime IDs is at: https://docs.microsoft.com/en-us/dotnet/core/rid-catalog
namespace CentrifyCLI
{
    [Serializable]
    class CentrifyCliConfig
    {
        public Runner.ServerProfile Profile = new Runner.ServerProfile();
        /// <summary>Defaults to {UserHome}/centrifycli.swagger.json in loadConfig() IF file exists, null otherwise.</summary>
        public string SwaggerDirectory;
        public bool Silent = false;
        public int Timeout;

        public override string ToString()
        {
            return $"{Profile.ToString()}\nSwaggerDirectory: {SwaggerDirectory}\nSilent: {Silent}\nTimeout: {Timeout}";
        }
    };

    [Command(ThrowOnUnexpectedArgument = false, AllowArgumentSeparator = true, ExtendedHelpText = @"
Examples:
  ccli /UserMgmt/GetUserInfo -token ""oauthtoken"" -url https://mycompany.my.centrify.com -ja id=myuser@mycompany.com
  ccli /UserMgmt/GetUserInfo -u myadmin@mycompany.com -pw adminpw -url https://mycompany.my.centrify.com -ja id=myuser@mycompany.com
  ccli -u myadmin@mycompany.com -url https://mycompany.my.centrify.com saveconfig
  ccli /UserMgmt/GetUserInfo -j ""{ ""id"": ""myuser@mycompany.com"" }""
  ccli /UserMgmt/GetUserInfo -ja id=myuser@mycompany.com
  ccli /UserMgmt/GetUserInfo -f payload.json
  ccli requesttoken -pw randomPassword
")]
    class Ccli
    {
        [Argument(0, "Command", "One of the following: {\n" +
            "|\t Path (starting with '/') from API Description at https://developer.centrify.com/reference, e.g. /UserMgmt/GetUserInfo\n" +
            "|\t bootstrap    - Bootstrap and configure the service for CLI usage.\n" +
            "|\t listConfig   - List saved configuration.\n" +
            "|\t saveConfig   - Save command-line options to configuration.\n" +
            "|\t listProfiles - List saved server profiles.\n" +
            "|\t saveProfile  - Save specified server profile.\n"+
            "|\t listAPIs     - Lists the APIs the current input knows about.\n" +
            "|\t findAPI      - List APIs matching the provided string.\n" +
            "|\t updateAPIs   - Force refresh of the cached Centrify API list.\n" +
            "|\t requestToken - Using specified client credentials, retrieve an OAuth token from the server.\n" +
            "|\t saveToken    - Parse out and save OAuth2 token for future use.\n" +
            "|\t version      - Prints version information.\n" +
            "|\t help         - Show help information.\n" +
            "}")]
        public string Run { get; }

        [Argument(1, ShowInHelpText = false)]
        public string FindString { get; }

        [Option("-app|--appid", Description = "OAuth2 application id; default is 'CentrifyCLI'")]
        public string OAuthAppId { get; }

        [Option("-u|--user", Description = "User to run the command as (or OAuth2 client if requesting a token).")]
        public string UserId {  get; }

        [Option("-pw|--password", Description = "Password for user (or OAuth2 client secret if requesting a token).")]
        public string Password {  get; }

        [Option("-token|--token", Description = "OAuth2 Token; enclose in quotes.  Can be saved to config with saveToken command.")]
        public string Token { get; }

        [Option("-url|--url", Description = "Host URL.")]
        public string URL { get; }

        [Option("-p|--profile", Description = "Profile name in the to load/save.  Either this or the username/password/URL/Tenant parameters are required.")]
        public string Profile {  get; }

        [Option("-j|--json", Description = "JSON input Source: JSON string to send.")]
        public string Json { get; }

        [Option("-f|--file", Description = "JSON input Source: JSON file to read and send.")]
        public string JsonFile { get; }

        [Option("-i|--stdin", "JSON input Source: Read JSON input from STDIN.  Without this, pipes/stdin are ignored.",  CommandOptionType.NoValue)]
        public bool JsonStdin { get; }
        
        [Option("-ja|--jarg", "JSON input Source: Value to pass as a JSON Parameter, e.g. -jarg foo=\"bar\".  You may have several of these.", CommandOptionType.MultipleValue)]
        public string[] JsonArg { get; }
        
        [Option("-t|--timeout", "Time in seconds to wait for a response, default: 60.  -1 is infinite (although the service times out after 5 minutes).", CommandOptionType.SingleValue)]
        public int? Timeout { get; }

        [Option("-o|--overwrite", "Overwrite the current config or profile on save.", CommandOptionType.NoValue)]
        public bool Overwrite { get; }

        [Option("-savepw|--savepassword", "Persist password in (clear text) to config/profile (not recommended).", CommandOptionType.NoValue)]
        public bool SavePassword { get; }

        [Option("-s|--silent", "Only display REST/error output (no progress text), default false. -silent, -silent=t, or -silent=true to enable", CommandOptionType.SingleOrNoValue)]
        public (bool HasValue, bool? Value) Silent { get; }

        ///<summary>Internal, for forcing to a specific swagger file version.</summary>
        [Option("-apilist|--apilist", Description = "Swagger Directory and Filename", ShowInHelpText = false)]
        public string SwaggerDirectory { get; }

        [Option("-br|--bootstraproles", "The roles to give access to the CLI, i.e. -br MyRole.  You may have several of these.  If not specified, default is sysadmin.", CommandOptionType.MultipleValue)]
        public string[] BootstrapRoles { get; }

        [Option("-breg|--bootstrapregexes", "The API regex to use for the CLI scope, i.e. -breg '.*'.  You may have several of these. If not specified, default is .*", CommandOptionType.MultipleValue)]
        public string[] BootstrapRegexes { get; }



        // Constants
        private const string FILENAME_BASE = "centrifycli";
        private const string SWAGGER_FILE = FILENAME_BASE + ".swagger.json";
        private const string PROFILES_DEFAULT = FILENAME_BASE + ".servers";
        private const string CONFIG_DEFAULT = FILENAME_BASE + ".config";
        private const string TOKENFILE_EXT = ".token";

        // Exit codes
        private const int SUCCESS = 0;
        private const int RUNCOMMAND_FAIL = 1;
        private const int VERB_FAIL = 2;
        private const int UNEXPECTED_FAIL = -1;

        private CentrifyCliConfig m_config = new CentrifyCliConfig();
        private Runner m_runner = new Runner();

        public static int Main(string[] args) => CommandLineApplication.Execute<Ccli>(args);

        /// <summary>Get the timeout (in milliseconds) to use for REST calls.</summary>
        private int GetTimeout()
        {
            return (m_config.Timeout == -1 ? m_config.Timeout : m_config.Timeout == 0 ? 60000 : m_config.Timeout * 1000);
        }

        /// <summary>Load json for REST calls; checks in this order: json stream, json, json file, jargs</summary>
        private string LoadJSON()
        {
            // From stdin
            if (JsonStdin)
            {
                string json = "";
                string line;
                while ((line = Console.ReadLine()) != null && line != "")
                {
                    json += line;
                }
                return json;
            }

            // From command line as string
            if (!String.IsNullOrEmpty(Json))
            {
                return Json;
            }

            // From file
            if (!String.IsNullOrEmpty(JsonFile))
            {
                using (StreamReader file = File.OpenText(JsonFile))
                {
                    return file.ReadToEnd();
                }
            }

            // Built from command line jargs
            if ((JsonArg != null) && (JsonArg.Length > 0))
            {
                // Split on equals.  Enquote if needed.
                string json = "{\n";
                foreach (string j in JsonArg)
                {
                    int equals = j.IndexOf('=');
                    if (equals < 0)
                    {
                        WriteErrorText("Error with JArg: " + j + "; use Name=\"\" for an empty value.");
                    }
                    else
                    {
                        json += ((json.Length > 3) ? ",\n\"" : "\"") + j.Substring(0, equals) + "\":\"" + j.Substring(equals + 1) + "\"";
                    }
                }
                json+= "\n}";
                return json;
            }

            // No json
            return "";
        }

        /// <summary>Load config, from user directory and applies command line overrides</summary>
        private bool LoadConfig()
        {
            try
            {
                bool silent = false;
                if (Silent.HasValue)
                {
                    // -silent with no value implies true
                    silent = (!Silent.Value.HasValue || Silent.Value.Value);
                }

                // Load saved config (command line args will override values)
                string dir = Runner.GetUserFilePath(CONFIG_DEFAULT);
                if (!File.Exists(dir))
                {
                    ConditionalWrite($"No saved config available at {dir}.", silent);
                }
                else
                {
                    string importJson = System.IO.File.ReadAllText(dir);
                    m_config = Newtonsoft.Json.JsonConvert.DeserializeObject<CentrifyCliConfig>(importJson);
                    if (!Silent.HasValue)
                    {
                        silent = m_config.Silent;
                    }
                    ConditionalWrite($"Loaded config from {dir}.", silent);
                }

                // Load profiles
                m_runner.LoadServerList(Runner.GetUserFilePath(PROFILES_DEFAULT), silent);
                string profileName = m_config.Profile.NickName;
                if (!String.IsNullOrEmpty(Profile))
                {
                    // Note: config.Profile is not the name, but rather the values of the saved profile in config.
                    if (m_runner.ServerList.TryGetValue(Profile.ToLower(), out Runner.ServerProfile profile))
                    {
                        ConditionalWrite($"Using profile {Profile}.", silent);
                        m_config.Profile = profile;
                        profileName = m_config.Profile.NickName;
                    }
                    else
                    {
                        // Set config profile to the specified name, for saveProfile.
                        // profileName stays as the default in this case, so we load token from the default location
                        ConditionalWrite($"Requested profile {Profile} does not exist.", silent);
                        m_config.Profile.NickName = Profile;
                    }
                }

                // OAuth token (prefered authenication)
                // Command line has precedence
                // You can set Token to "" on command line to force no OAuth
                if (Token != null)
                {
                    ConditionalWrite($"Using token from command line.", silent);
                    m_config.Profile.OAuthToken = String.IsNullOrEmpty(Token) ? "" : Runner.ParseToken(Token);
                }
                else
                {
                    // Use saved token (if any)
                    string tokenFile = GetTokenFileName(profileName);
                    if (File.Exists(tokenFile))
                    {
                        ConditionalWrite($"Using token from {tokenFile}.", silent);
                        using (StreamReader file = File.OpenText(tokenFile))
                        {
                            m_config.Profile.OAuthToken = file.ReadToEnd();
                        }
                    }
                }

                // OAuth2 Application Id
                if (!String.IsNullOrEmpty(OAuthAppId))
                {
                    m_config.Profile.OAuthAppId = OAuthAppId;
                }
                else if (String.IsNullOrEmpty(m_config.Profile.OAuthAppId))
                {
                    m_config.Profile.OAuthAppId = "CentrifyCLI";
                }

                // OAuth2 client/secret or user name/password
                if (!String.IsNullOrEmpty(UserId))
                {
                    m_config.Profile.UserName = UserId;
                }
                if (!String.IsNullOrEmpty(Password))
                {
                    m_config.Profile.Password = Password;
                }

                if (!String.IsNullOrEmpty(URL))
                {
                    m_config.Profile.URL = URL;
                }

                m_config.SwaggerDirectory = !String.IsNullOrEmpty(SwaggerDirectory) ? SwaggerDirectory : Runner.GetUserFilePath(SWAGGER_FILE);
                m_config.Timeout = Timeout ?? 60;
                m_config.Silent = silent;
                return true;
            }
            catch (Exception e)
            {
                WriteErrorText($"Unexpected error loading config: {e.Message}");
                return false;
            }
        }

        /// <summary>Get of token file</summary>
        private string GetTokenFileName(string nickName)
        {
            string tokenFile = FILENAME_BASE;
            if (!string.IsNullOrWhiteSpace(nickName))
            {
                tokenFile += '.' + nickName.ToLower();
            }
            tokenFile += TOKENFILE_EXT;
            return Runner.GetUserFilePath(tokenFile);
        }

        /// <summary>Save token to file</summary>
        private void SaveToken(string nickName, string token)
        {
            string tokenFile = GetTokenFileName(nickName);
            using (StreamWriter file = File.CreateText(tokenFile))
            {
                file.Write(token);
            }
            ConditionalWrite($"Saved token to {tokenFile}.");
        }

        private bool SaveConfig()
        {
            return SaveConfig(false);
        }

        /// <summary>Save config to file</summary>
        private bool SaveConfig(bool force)
        {
            string dir = Runner.GetUserFilePath(CONFIG_DEFAULT);
            if ((File.Exists(dir)) && (!Overwrite) && (!force))
            {
                WriteErrorText("Must specify -o or --overwrite to overwrite config at " + dir);
                return false;
            }

            // No Profile name in saved config (its the default profile)
            string profileName = m_config.Profile.NickName;
            m_config.Profile.NickName = null;

            // Remove password before save if needed
            string password = m_config.Profile.Password;
            if (!SavePassword)
            {
                m_config.Profile.Password = null;
            }

            string configText = Newtonsoft.Json.JsonConvert.SerializeObject(m_config, Newtonsoft.Json.Formatting.Indented);
            File.WriteAllText(dir, configText);

            // If we have a provided token, save it too
            if (m_config.Profile.OAuthToken != null)
            {
                SaveToken(null, Token);
            }

            // Restore profile name and password
            m_config.Profile.NickName = profileName;
            m_config.Profile.Password = password;

            ConditionalWrite("Config saved to " + dir);
            return true;
        }

        private bool BootstrapService()
        {
            List<string> roles = new List<string>();
            if(BootstrapRoles != null)
            {
                roles.AddRange(BootstrapRoles);
            }
            else
            {
                roles.Add("sysadmin");
            }

            List<string> regexes = new List<string>();
            if(BootstrapRegexes != null)
            {
                regexes.AddRange(BootstrapRegexes);
            }
            else
            {
                regexes.Add(".*");
            }

            // Need to do some minimal prep to call to backend
            int timeout = GetTimeout();
            ConditionalWrite($"Authenticating with user {m_config.Profile.UserName}");
            Tuple<Runner.ResultCode, string> authResult = m_runner.Authenticate(m_config, timeout);
            if (authResult.Item1 != Runner.ResultCode.Success)
            {
                WriteErrorText($"Failure during bootstrap - could not authenticate user.");
                return false;
            }

            try
            {
                string appId = null;

                // Look for the app to see if its already there, if so, jsut update roles/regexes?
                Dictionary<string, string> searchArgs = new Dictionary<string, string>()
                {
                    { "Script", "select ID from Application where ServiceName = 'CentrifyCLI'" }
                };

                var searchResult = m_runner.SimpleCall(timeout, "/redrock/query", searchArgs);
                if(searchResult["Result"]["Results"].Count > 0)
                {
                    appId = searchResult["Result"]["Results"][0]["Row"]["ID"];
                }

                if (appId == null)
                {
                    // Create the app (if needed):
                    //  /saasmanage/importappfromtemplate { ID: "OAuth2ServerClient" }
                    //  Result: _RowKey => App ID
                    Dictionary<string, string[]> importAppArgs = new Dictionary<string, string[]>()
                    {
                        { "ID", new string[] { "OAuth2ServerClient" } }
                    };

                    var addResult = m_runner.SimpleCall(timeout, "/saasmanage/importappfromtemplate", importAppArgs);
                    appId = addResult["Result"][0]["_RowKey"];
                }

                // Resolve roles to IDs
                //  Role -> ID
                Dictionary<string, string> roleToIds = new Dictionary<string, string>();
                foreach(string role in roles)
                {
                    var roleToId = m_runner.SimpleCall(timeout, $"/saasmanage/getroleidfromname?roleName={role}", null);
                    string roleId = roleToId["Result"];
                    roleToIds.Add(role, roleId);
                }
                                
                // Set permission for the roles on the app
                //  /saasmanage/setapplicationpermissions { ID == RowKey == PVID: "AppId", Grants: { Principal: "System Administrator",  PrincipalId: "sysadmin", PType: "Role", Rights: "View,Execute"  } }
                Dictionary<string, object> appPermsArgs = new Dictionary<string, object>()
                {
                    { "ID", appId },
                    { "RowKey", appId },
                    { "PVID", appId },
                    { "Grants", new List<dynamic>() }
                };

                var grants = (List<dynamic>)appPermsArgs["Grants"];
                foreach(var item in roleToIds)
                {
                    grants.Add(new { Principal = item.Key, PrincipalId = item.Value, PType = "Role", Rights = "View,Execute" });
                }
                
                
                // Add each role id to appPermsArgs
                m_runner.SimpleCall(timeout, "/saasmanage/setapplicationpermissions", appPermsArgs);

                // Save out the app with all proper bits
                //  /saasmanage/updateapplicationde {}         
                Dictionary<string, object> updateAppArgs = new Dictionary<string, object>()
                {
                    { "_RowKey", appId },
                    {  "TokenType", "JwtRS256" },
                    { "Name", "CentrifyCLI" },
                    { "ServiceName", "CentrifyCLI" },
                    { "Description", "CentrifyCLI OAuth2 Application" },
                    {
                        "OAuthProfile", new Dictionary<string, object>()
                        {
                            { "ClientIDType", "confidential" },
                            { "MustBeOauthClient", false },
                            { "TokenLifetimeString", "1:00:00" },
                            { "AllowedAuth", "ClientCreds,ResourceCreds"},
                            { "TargetIsUs", true },
                            { "KnownScopes", new List<dynamic>() }                            
                        }
                    }
                };
                
                var scopes = (List<dynamic>)((Dictionary<string, object>)updateAppArgs["OAuthProfile"])["KnownScopes"];
                scopes.Add(new { Scope = "ccli", Mode = "RestFilter", AllowedRest = regexes.ToArray() });

                var updateResult = m_runner.SimpleCall(timeout, "/saasmanage/updateapplicationde", updateAppArgs);

                return true;
            }
            catch(Exception ex)
            {
                WriteErrorText($"Failure during bootstrap: {ex.Message}");
                return false;
            }            
        }

        /// <summary>Save specific profile to file</summary>
        private bool SaveProfile()
        {
            if (String.IsNullOrWhiteSpace(m_config.Profile.NickName))
            {
                WriteErrorText("Cannot save to an empty Profile nickname.");
                return false;
            }

            // Remove password before save if needed
            string password = m_config.Profile.Password;
            if (!SavePassword)
            {
                m_config.Profile.Password = null;
            }

            string nickName = m_config.Profile.NickName.ToLower();
            string saveFile = Runner.GetUserFilePath(PROFILES_DEFAULT);
            m_runner.ServerList[nickName] = m_config.Profile;
            m_runner.SaveServerList(saveFile);

            // If we have a provided token, save it too
            if (m_config.Profile.OAuthToken != null)
            {
                SaveToken(nickName, Token);
            }

            // Restore password
            m_config.Profile.Password = password;

            ConditionalWrite($"Saved profile {nickName} to {saveFile}");
            return true;
        }

        /// <summary>Request and save OAuth token</summary>
        private bool RequestToken()
        {
            var run = m_runner.OAuth2_GenerateTokenRequest(m_config, GetTimeout());
            if (run.Result.Item1 == Runner.ResultCode.Success)
            {
                SaveToken(m_config.Profile.NickName, run.Result.Item2);
                return true;
            }
            else
            {
                WriteErrorText("Failed to fetch Token: " + run.Result.Item2);
                return false;
            }
        }

        /// <summary>Log text if needed</summary>
        private void ConditionalWrite(string s)
        {
            ConditionalWrite(s, m_config.Silent);
        }

        /// <summary>Log text if needed</summary>
        public static void ConditionalWrite(string s, bool silent)
        {
            if (!silent)
            {
                Console.WriteLine(s);
            }
        }

        /// <summary>Output error text (red) to console</summary>
        public static void WriteErrorText(string s)
        {
            ConsoleColor current = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(s);
            Console.ForegroundColor = current;
        }

        /// <summary>Excute CCLI</summary>
        private int OnExecute(CommandLineApplication app) 
        {
            if (!LoadConfig())
            {
                return UNEXPECTED_FAIL;
            }

            if (String.IsNullOrEmpty(Run))
            {
                app.ShowHelp();
                return VERB_FAIL;
            }

            string commandPath = null;
            if (Run.StartsWith('/'))
            {
                commandPath = Run;
            }
            else
            {
                try
                {
                    switch (Run.ToLower())
                    {
                        case "listconfig":
                            Console.WriteLine(m_config.ToString());
                            break;
                        case "listprofiles":
                            Console.WriteLine(string.Join("\n", m_runner.ServerList.Select(x => x.Value)));
                            break;
                        case "bootstrap":
                            if(!BootstrapService())
                            {                            
                                return VERB_FAIL;
                            }
                            else
                            {                                                                
                                ConditionalWrite($"Bootstrap complete, requesting initial user token as well.");
                                if (!RequestToken())
                                {
                                    return VERB_FAIL;
                                }

                                ConditionalWrite($"Bootstrap complete, initial user token retrieved, saving config.");
                                if(!SaveConfig(true))
                                {
                                    return VERB_FAIL;
                                }
                            }
                            break;
                        case "saveconfig":
                            if (!SaveConfig())
                            {
                                return VERB_FAIL;
                            }
                            break;
                        case "saveprofile":
                            if (!SaveProfile())
                            {
                                return VERB_FAIL;
                            }
                            break;
                        case "listapis":
                            if (!m_runner.LoadSwagger(m_config))
                            {
                                return VERB_FAIL;
                            }
                            Console.WriteLine(m_runner.ListAPIs());
                            break;
                        case "findapi":
                            if (!m_runner.LoadSwagger(m_config))
                            {
                                return VERB_FAIL;
                            }
                            Console.WriteLine(m_runner.FindAPIMatch(FindString));
                            break;
                        case "updateapis":  // rest point is "/vfslow/lib/api/swagger.json"
                            if (!m_runner.GetSwagger(m_config))
                            {
                                return VERB_FAIL;
                            }
                            ConditionalWrite("API swagger updated.");
                            break;
                        case "random":
                            Console.WriteLine(Runner.RandomString(20));
                            break;
                        case "requesttoken":
                            if (!RequestToken())
                            {
                                return VERB_FAIL;
                            }
                            break;
                        case "savetoken":
                        {
                            // Parsed as part of command line processing
                            if (m_config.Profile.OAuthToken == null || m_config.Profile.OAuthToken.Length < 5)   // It should be over 600
                            {
                                WriteErrorText("No token available or token too short.");
                                File.Delete(GetTokenFileName(m_config.Profile.NickName));
                                return VERB_FAIL;
                            }
                            else
                            {
                                SaveToken(m_config.Profile.NickName, m_config.Profile.OAuthToken);
                            }
                            break;
                        }
                        case "version":
                        {
                            var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(System.Reflection.Assembly.GetEntryAssembly().Location);
                            Console.WriteLine("CentrifyCLI:\n{\n  \"Version\": \"" + version.FileVersion + "\"\n  \"Copyright\": \"" + version.LegalCopyright + "\"\n}");
                            if (!string.IsNullOrEmpty(m_config.Profile.URL))
                            {
                                Console.WriteLine("Centrify Cloud:");
                                commandPath = "/sysinfo/version";
                                m_config.Silent = true;
                            }
                            break;
                        }
                        case "help":
                            app.ShowHelp();
                            break;
                        default:
                            WriteErrorText("Invalid Command: " + Run);
                            app.ShowHelp();
                            return VERB_FAIL;
                    }
                }
                catch (Exception e)
                {
                    WriteErrorText($"Unexpected error processing command {Run}: {e.Message}");
                    return UNEXPECTED_FAIL;
                }
            }

            if (commandPath != null)
            {
                return (RunCommand(commandPath) ? SUCCESS : RUNCOMMAND_FAIL);
            }
            return SUCCESS;
        }

        /// <summary>Run REST command</summary>
        private bool RunCommand(string call)
        {
            bool ret = false;
            string result = null;

            try
            {
                int timeout = GetTimeout();

                // Authenicate if needed
                // OAuth token is the preferred authentication method
                if (String.IsNullOrEmpty(m_config.Profile.OAuthToken))
                {
                    if (String.IsNullOrEmpty(m_config.Profile.UserName))
                    {
                        ConditionalWrite($"No token or user to authenicate; skipping authenication.");
                        m_runner.InitializeClient(m_config.Profile.URL);
                    }
                    else
                    {
                        ConditionalWrite($"Authenticating with user {m_config.Profile.UserName}");
                        Tuple<Runner.ResultCode, string> authResult = m_runner.Authenticate(m_config, timeout);
                        if (authResult.Item1 != Runner.ResultCode.Success)
                        {
                            bool isException = (authResult.Item1 == Runner.ResultCode.Exception);
                            result = Runner.MakeFailResult(isException ? null : authResult.Item2, $"Could not authenticate user {m_config.Profile.UserName}: {authResult.Item1}", authResult.Item2);
                            ret = false;
                        }
                    }
                }
                else
                {
                    ConditionalWrite("Using Token for Authentication.");
                    m_runner.InitializeClient(m_config.Profile.URL, m_config.Profile.OAuthToken);
                }

                if (result == null)
                {
                    ConditionalWrite($"Calling {call}");
                    var runTask = m_runner.PlaceCall(call, LoadJSON());
                    if (runTask.Wait(timeout))
                    {
                        Tuple<Runner.ResultCode, string> callResult = runTask.Result;
                        if (callResult.Item1 != Runner.ResultCode.Success)
                        {
                            ConditionalWrite($"Request failed ({call}): {callResult.Item1}");
                            result = Runner.MakeFailResult(null, $"Request failed ({call}): {callResult.Item1}", callResult.Item2);
                            ret = false;
                        }
                        else
                        {   //  Success
                            Tuple<bool, string> results = m_runner.ParseResults(callResult.Item2);
                            result = results.Item2;
                            ret = results.Item1;
                        }
                    }
                    else
                    {
                        ConditionalWrite($"Request timed out ({call}): check cloud URL.");
                        result = Runner.MakeFailResult(null, $"Request failed ({call}): {Runner.ResultCode.Timeout}", $"Request timed out ({call}).");
                        ret = false;
                    }
                }
            }
            catch (Exception e)
            {
                result = Runner.MakeFailResult(null, $"Unexpected error executing request {call}.", e.Message);
                ret = false;
            }

            Console.WriteLine(result);
            return ret;
        }
    }
}
