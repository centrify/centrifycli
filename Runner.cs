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
using System.Text;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.IO;
using System.Net;

namespace CentrifyCLI
{
    /// <summary>The Centrify-specific logic and knowledge.</summary>
    class Runner
    {
        // Constants
        private const string FAILED = "FAILED: ";
        public static readonly TimeSpan SWAGGER_REFRESH = TimeSpan.FromDays(15);

        /// <summary>Result codes for REST calls</summary>
        public enum ResultCode { Success, Redirected, Unauthorized, NotFound, Exception, Failed, Timeout};

        /// <summary>Centrify service URL.</summary>
        private string m_url ="";
 
        /// <summary>List of APIs for the drop-down/easy reference.<para/>
        /// These each have a structure of Group/Api/Path/Reference/Sample.</summary>
        private JObject m_apiCalls = new JObject();

        /// <summary>Use the one restUpdater for the entire short session</summary>
        private RestUpdater m_restUpdater = new RestUpdater();

        /// <summary>Record that can be stored as a server profile.</summary>
        [Serializable]
        public class ServerProfile
        {
            /// <summary>What to call this connection.</summary>
            public string NickName;
            /// <summary>Tenant URL</summary>
            public string URL;
            /// <summary>OAuth application id</summary>
            public string OAuthAppId;
            /// <summary>User name for authentication</summary>
            public string UserName;
            /// <summary>User password for authentication</summary>
            public string Password;
            /// <summary>OAuth token</summary>
            [JsonIgnore]
            public string OAuthToken;

            public override string ToString()
            {
                string name = (String.IsNullOrEmpty(NickName) ? "-default-" : NickName);
                return $"Profile {name}: URL: '{URL}' AppId: '{OAuthAppId}' User: '{UserName}'";
            }
        }

        /// <summary>Available server profiles, by name</summary>
        public Dictionary<string, ServerProfile> ServerList { get; private set; } = new Dictionary<string, ServerProfile>();

        /// <summary>Parse contents from a REST response into JObject, handling errors.</summary>
        private JObject ParseContentsToJObject(string contents)
        {
            if (string.IsNullOrWhiteSpace(contents))
            {
                return null;
            }

            JObject result = null;
            try
            {
                result = JObject.Parse(contents);
            }
            catch (Exception e)
            {
                result = new JObject()
                {
                    { "success", false },
                    { "contents", contents },
                    { "exception", e.Message },
                };
            }

            return result;
        }

        // Roughly: http://stackoverflow.com/questions/3404421/password-masking-console-application
        public static string ReadMaskedPassword(bool prompt)
        {
            ConsoleKeyInfo key;
            string password = null;

            if (prompt) Console.Write("Password: ");

            do
            {
                // Read a character without echoing it
                key = Console.ReadKey(true);

                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    password += key.KeyChar;
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && password != null && password.Length > 0)
                    {
                        password = password.Substring(0, password.Length - 1);
                        Console.Write("\b \b");
                    }
                }
            } while (key.Key != ConsoleKey.Enter);

            Console.WriteLine();
            return password;
        }

        /// <summary>Authenticate the user via username/password/etc.<para/>
        /// OAuth token is the preferred method of authenication; this exists for ease of use</summary>
        /// <param name="config">Contains config info, including profile to use</param>
        /// <param name="timeout">Timeout is milliserconds for REST calls</param>
        /// <returns>Tuple of success or failure reason and message or results.</returns>
        public Tuple<ResultCode, string> Authenticate(CentrifyCliConfig config, int timeout)
        {
            ServerProfile profile = config.Profile;

            try
            {
                if (string.IsNullOrWhiteSpace(profile.UserName))
                {
                    return new Tuple<ResultCode, string>(ResultCode.NotFound, $"No user in config to authenticate.");
                }

                InitializeClient(profile.URL);

                // Do StartAuthentication
                string endpoint = "/Security/StartAuthentication";
                Dictionary<string, string> args = new Dictionary<string, string>()
                {
                    { "User", profile.UserName },
                    { "Version", "1.0" }
                };

                var authTask = PlaceCall(endpoint, JsonConvert.SerializeObject(args));
                if (!authTask.Wait(timeout))
                {
                    return new Tuple<ResultCode, string>(ResultCode.Timeout, $"Request timed out ({endpoint}).");
                }

                Tuple<Runner.ResultCode, string> callResult = authTask.Result;
                if (callResult.Item1 != ResultCode.Success)
                {
                    return new Tuple<ResultCode, string>(ResultCode.Failed, MakeFailResult(callResult.Item2, $"Authentication request failed ({endpoint}): {callResult.Item1}"));
                }

                // Remember session and tenant
                JObject resultSet = ParseContentsToJObject(callResult.Item2);
                if (!TryGetJObjectValue(resultSet, "Result", out JObject results))
                {
                    throw new ArgumentException($"Authentication results have no 'result' property ({endpoint}):\n{ResultToString(resultSet)}", "Result");
                }

                if (TryGetJObjectValue(results, "Redirect", out string redirect))
                {
                    Ccli.ConditionalWrite($"Authentication is redirected, use the prefered URL: {redirect}", config.Silent);
                    return new Tuple<ResultCode, string>(ResultCode.Redirected, redirect);
                }

                if (!TryGetJObjectValue(results, "SessionId", out string sessionId))
                {
                    throw new ArgumentException($"Authentication results are missing 'SessionId' ({endpoint}): {ResultToString(results)}", "SessionId");
                }

                if (!TryGetJObjectValue(results, "TenantId", out string tenantId))
                {
                    throw new ArgumentException($"Authentication results are missing 'TenantId' ({endpoint}): {ResultToString(results)}", "TenantId");
                }

                if (!TryGetJObjectValue(results, "Challenges", out JToken challenges))
                {
                    throw new ArgumentException($"Authentication results are missing 'Challenges' ({endpoint}): {ResultToString(results)}", "Challenges");
                }

                // If pw was supplied, and is one of the first mechs, use what was supplied automagically
                int passwordMechIdx = -1;
                if (profile.Password != null)
                {                    
                    // Present the option(s) to the user                    
                    for (int mechIdx = 0; mechIdx < challenges[0]["Mechanisms"].Children().Count() && passwordMechIdx == -1; mechIdx++)
                    {
                        if (challenges[0]["Mechanisms"][mechIdx]["Name"].Value<string>() == "UP")
                        {
                            passwordMechIdx = mechIdx;
                        }                        
                    }                    
                }
                                
                // Need to satisfy at least 1 challenge in each collection:
                for (int x = 0; x < challenges.Children().Count(); x++)
                {
                    int optionSelect = -1;

                    // If passwordMechIdx is set, we should auto-fill password first, do it
                    if (passwordMechIdx == -1)
                    {
                        // Present the option(s) to the user                    
                        for (int mechIdx = 0; mechIdx < challenges[x]["Mechanisms"].Children().Count(); mechIdx++)
                        {
                            Console.WriteLine("Option {0}: {1}", mechIdx, MechToDescription(challenges[x]["Mechanisms"][mechIdx]));
                        }                     

                        if (challenges[x]["Mechanisms"].Children().Count() == 1)
                        {
                            optionSelect = 0;
                        }
                        else
                        {
                            while (optionSelect < 0 || optionSelect > challenges[x]["Mechanisms"].Children().Count())
                            {
                                Console.Write("Select option and press enter: ");
                                string optEntered = Console.ReadLine();
                                int.TryParse(optEntered, out optionSelect);
                            }
                        }
                    }
                    else
                    {
                        optionSelect = passwordMechIdx;
                        passwordMechIdx = -1;
                    }

                    try
                    {
                        var newChallenges = AdvanceForMech(timeout, tenantId, sessionId, challenges[x]["Mechanisms"][optionSelect], profile);
                        if(newChallenges != null)
                        {
                            challenges = newChallenges;
                            x = -1;
                        }
                    }
                    catch (Exception ex)
                    {
                        return new Tuple<ResultCode, string>(ResultCode.Failed, ex.Message);
                    }
                }
            }
            catch (Exception e)
            {
                Exception i = e;
                string allMessages = "";
                // De-dup; sometimes they double up.
                while (i != null)
                {
                    if (!allMessages.Contains(i.Message)) allMessages += i.Message + "  " + Environment.NewLine;
                    i = i.InnerException;
                }
                return new Tuple<ResultCode, string>(ResultCode.Exception, allMessages);
            }

            m_url = profile.URL;
            return new Tuple<ResultCode, string>(ResultCode.Success, "");
        }

        private dynamic AdvanceForMech(int timeout, string tenantId, string sessionId, dynamic mech, ServerProfile profile)
        {
            Dictionary<string, dynamic> advanceArgs = new Dictionary<string, dynamic>();
            advanceArgs["TenantId"] = tenantId;
            advanceArgs["SessionId"] = sessionId;
            advanceArgs["MechanismId"] = mech["MechanismId"];
            advanceArgs["PersistentLogin"] = false;

            bool autoFillPassword = (mech["Name"] == "UP" && profile.Password != null);

            // Write prompt (unless auto-filling)
            if (!autoFillPassword)
            {
                Console.Write(MechToPrompt(mech));
            }                           

            // Read or poll for response.  For StartTextOob we simplify and require user to enter the response, rather
            //  than simultaenously prompting and polling, though this can be done as well.
            string answerType = mech["AnswerType"];
            switch (answerType)
            {
                case "Text":
                case "StartTextOob":
                    {
                        if (answerType == "StartTextOob")
                        {
                            // First we start oob, to get the mech activated
                            advanceArgs["Action"] = "StartOOB";
                            if(!PlaceCall("/security/advanceauthentication", JsonConvert.SerializeObject(advanceArgs)).Wait(timeout))
                            {
                                throw new ApplicationException("Request timed out (/security/advanceauthentication)");                                
                            }
                        }

                        // Now prompt for the value to submit and do so
                        string promptResponse = null;
                        if (autoFillPassword)
                        {
                            promptResponse = profile.Password;
                        }
                        else
                        {
                            promptResponse = ReadMaskedPassword(false); 
                        }

                        advanceArgs["Answer"] = promptResponse;
                        advanceArgs["Action"] = "Answer";
                        var result = SimpleCall(timeout, "/security/advanceauthentication", advanceArgs);
                        
                        if(result["Result"]["Summary"] == "NewPackage")
                        {
                            return result["Result"]["Challenges"];                            
                        }

                        if (!(result["Result"]["Summary"] == "StartNextChallenge" ||
                              result["Result"]["Summary"] == "LoginSuccess"))
                        {
                            throw new ApplicationException(result["Message"]);
                        }
                    }
                    break;
                case "StartOob":
                    // Pure out of band mech, simply poll until complete or fail                    
                    advanceArgs["Action"] = "StartOOB";
                    SimpleCall(timeout, "/security/advanceauthentication", advanceArgs);

                    // Poll
                    advanceArgs["Action"] = "Poll";
                    dynamic pollResult = null;
                    do
                    {
                        Console.Write(".");
                        pollResult = SimpleCall(timeout, "/security/advanceauthentication", advanceArgs);
                        System.Threading.Thread.Sleep(1000);
                    } while (pollResult["Result"]["Summary"] == "OobPending");

                    // We are done polling, did it work ?
                    if (pollResult["Result"]["Summary"] == "NewPackage")
                    {
                        return pollResult["Result"]["Challenges"];
                    }
                    
                    if (!(pollResult["Result"]["Summary"] == "StartNextChallenge" ||
                          pollResult["Result"]["Summary"] == "LoginSuccess"))
                    {
                        throw new ApplicationException(pollResult["Message"]);
                    }
                    break;
            }

            return null;
        }

        public const string OneTimePassCode = "OTP";
        public const string OathPassCode = "OATH";
        public const string PhoneFactor = "PF";
        public const string Sms = "SMS";
        public const string Email = "EMAIL";
        public const string PasswordReset = "RESET";
        public const string SecurityQuestion = "SQ";

        private static string MechToDescription(dynamic mech)
        {
            string mechName = mech["Name"];

            try
            {
                return mech["PromptSelectMech"];
            }
            catch { /* Doesn't support this property */ }

            switch (mechName)
            {
                case "UP":
                    return "Password";
                case "SMS":
                    return string.Format("SMS to number ending in {0}", mech["PartialDeviceAddress"]);
                case "EMAIL":
                    return string.Format("Email to address ending with {0}", mech["PartialAddress"]);
                case "PF":
                    return string.Format("Phone call to number ending with {0}", mech["PartialPhoneNumber"]);
                case "OATH":
                    return string.Format("OATH compatible client");
                case "SQ":
                    return string.Format("Security Question");
                default:
                    return mechName;
            }
        }

        private static string MechToPrompt(dynamic mech)
        {
            string mechName = mech["Name"];
            try
            {
                string servicePrompt = mech["PromptMechChosen"];
                if(!string.IsNullOrEmpty(servicePrompt))
                {
                    if (!servicePrompt.EndsWith(":"))
                    {
                        return servicePrompt + ": ";
                    }
                    else
                    {
                        return servicePrompt + " ";
                    }
                }
            }
            catch { /* Doesn't support this property */ }
            switch (mechName)
            {
                case "UP":
                    return "Password: ";
                case "SMS":
                    return string.Format("Enter the code sent via SMS to number ending in {0}: ", mech["PartialDeviceAddress"]);
                case "EMAIL":
                    return string.Format("Please click or open the link sent to the email to address ending with {0}.", mech["PartialAddress"]);
                case "PF":
                    return string.Format("Calling number ending with {0}, please follow the spoken prompt.", mech["PartialPhoneNumber"]);
                case "OATH":
                    return string.Format("Enter your current OATH code: ");
                case "SQ":
                    return string.Format("Enter the response to your secret question: ");
                default:
                    return mechName;
            }
        }

        /// <summary>Call the rest endpoint with the JSON.<para/>
        /// Authentication has already set the URL.</summary>
        /// <param name="endpoint">Path to REST call, starts with a slash.</param>
        /// <param name="json">Json payload</param>
        /// <returns>Task with the result code and payload of the REST call</returns>
        public async Task<Tuple<ResultCode, string>> PlaceCall(string endpoint, string json)
        {
            RestUpdater.RESTCall restCall = new RestUpdater.RESTCall()
            {
                Endpoint = endpoint,
                JsonTemplate = json
            };
            HttpResponseMessage response = null;
            try
            {
                response = await m_restUpdater.NewRequestAsync(m_url, restCall);
            }
            catch (System.Threading.Tasks.TaskCanceledException)
            {
                return new Tuple<ResultCode, string>(ResultCode.Timeout, $"Request timed out or canceled ({endpoint}).");
            }

            HttpStatusCode statusCode = response.StatusCode;
            string contents = await response.Content.ReadAsStringAsync();
            switch (statusCode)
            {
                case HttpStatusCode.OK:
                     return new Tuple<ResultCode, string>(ResultCode.Success, contents);
                 case HttpStatusCode.Unauthorized:
                    return new Tuple<ResultCode, string>(ResultCode.Unauthorized, $"Access to {endpoint} not allowed.");
                case HttpStatusCode.NotFound:
                    return new Tuple<ResultCode, string>(ResultCode.NotFound, $"Endpoint {endpoint} not found.");
                default:
                    return new Tuple<ResultCode, string>(ResultCode.Failed, $"Unexpected response status from {endpoint}: {statusCode} - {contents}");
            }
        }

        // Wraps PlaceCall to simplify calling pattern:
        //  Throws exception on API fail or timeout (see ex.Message)
        //  Returns Result object as simple Dictionary
        public dynamic SimpleCall(int timeout, string endpoint, object args)
        {
            var call = PlaceCall(endpoint, JsonConvert.SerializeObject(args));
            if (!call.Wait(timeout))
            {
                throw new ApplicationException($"Request timed out ({endpoint})");
            }

            var callResult = call.Result;
            if (callResult.Item1 != ResultCode.Success)
            {
                throw new ApplicationException(MakeFailResult(callResult.Item2, $"API call failed ({endpoint}): {callResult.Item1}"));                
            }

            return ParseContentsToJObject(callResult.Item2);
        }

        /// <summary>Returns the path to a user file.</summary>
        /// <param name="fileName">filename to generate path for</param>
        /// <returns>Platform appropriate path string from the environmental settings</returns>
        public static string GetUserFilePath(string filename)
        {
            string userDir = null;
            if ((Environment.OSVersion.Platform == PlatformID.Unix) || (Environment.OSVersion.Platform == PlatformID.MacOSX))
            {
                userDir = Environment.GetEnvironmentVariable("HOME") + "/";
            }
            else
            {
                userDir = Environment.ExpandEnvironmentVariables("%HOMEDRIVE%%HOMEPATH%") + "\\";
            }

            return userDir + filename;
        }


        /// <summary>Load server profiles.</summary>
        /// <param name="fileName">File to load server profiles from</param>
        /// <param name="silent">Process logging disabled</param>
        /// <returns>Number of profiles loaded</returns>
        public int LoadServerList(string fileName, bool silent)
        {
            if (File.Exists(fileName))
            {
                try
                {
                    string importJson = System.IO.File.ReadAllText(fileName);
                    ServerList = JsonConvert.DeserializeObject<Dictionary<string, ServerProfile>>(importJson);
                }
                catch (Exception e)
                {
                    Ccli.ConditionalWrite($"Error parsing Server Profiles from {fileName}: {e.Message}", silent);
                    return -1;
                }
            }
            return ServerList.Count;
        }

        /// <summary>Save configured server profiles.</summary>
        /// <param name="fileName">File to save server profiles to</param>
        /// <returns></returns>
        public void SaveServerList(string fileName)
        {
            using (StreamWriter sw = new StreamWriter(fileName))
            {
                JsonSerializer serializer = new JsonSerializer();
                serializer.Serialize(sw, ServerList);
            }
        }

        /// <summary>Get latest swagger definitions from cloud.</summary>
        /// <param name="config">Contains config info, including profile to use</param>
        /// <returns>Success or failure</returns>
        public bool GetSwagger(CentrifyCliConfig config)
        {
            try
            {
                Ccli.ConditionalWrite($"Fetching latest swagger definitions from cloud.", config.Silent);

                // Doesn't require auth
                InitializeClient(config.Profile.URL);
                var runTask = PlaceCall("/vfslow/lib/api/swagger.json", "");
                runTask.Wait();
                Tuple<Runner.ResultCode, string> callResult = runTask.Result;

                if (callResult.Item1 == Runner.ResultCode.Success)
                {
                    // Write item2 to swagger.json file.  There's no JSON to process.
                    using (StreamWriter file = File.CreateText(config.SwaggerDirectory))
                    {
                        file.Write(callResult.Item2);
                    }
                    return true;
                }
                else
                {
                    Ccli.WriteErrorText($"Error fetching swagger definitions from cloud: {callResult}");
                }
            }
            catch (Exception e)
            {
                Ccli.WriteErrorText($"Exception fetching swagger definitions from cloud: {e.Message}");
            }

            return false;
        }

        /// <summary>Loads the swagger.json file from, typically, depot2\Cloud\Lib\Api\swagger.json
        /// Builds API Resource from it.</summary>
        /// <param name="config">Contains config info, including profile to use</param>
        /// <returns>Success or failure</returns>
        public bool LoadSwagger(CentrifyCliConfig config)
        {
            string swaggerPath = config.SwaggerDirectory;
            if (String.IsNullOrEmpty(swaggerPath))
            {
                Ccli.WriteErrorText("No swagger path defined in config.");
                return false;
            }

            Ccli.ConditionalWrite($"Loading swagger definitions from {swaggerPath}", config.Silent);
            bool exists = File.Exists(swaggerPath);
            if ((!exists) || (File.GetCreationTimeUtc(swaggerPath) < (DateTime.UtcNow - SWAGGER_REFRESH)))
            {
                // Fetch from cloud if no swagger or swagger is 'old'
                if (!GetSwagger(config))
                {
                    if (exists)
                    {
                        Ccli.ConditionalWrite($"Using existing swagger defintiions.", config.Silent);
                    }
                    else
                    {
                        Ccli.WriteErrorText($"No swagger definitions available from cloud.");
                        return false;
                    }
                }
            }

            JObject swagSet = null;
            try
            {
                using (StreamReader file = File.OpenText(swaggerPath))
                using (JsonTextReader reader = new JsonTextReader(file))
                {
                    swagSet = (JObject)JToken.ReadFrom(reader);
                }
            }
            catch (Exception e)
            {
                Ccli.WriteErrorText($"Error loading swagger definitions from {swaggerPath}: {e.Message}");
                return false;
            }

            JArray calls = new JArray();
            foreach (JProperty path in swagSet["paths"])
            {
                JProperty restPath = new JProperty("path", (string)path.Name);
                JProperty group = new JProperty("group", (string)path.First["post"]["tags"].First);
                string[] pathBits = ((string)path.Name).Split(new char[] { '/' });
                JProperty desc = new JProperty("api", pathBits[pathBits.Length - 1]);
                JProperty reference = new JProperty("reference", (string)path.First["post"]["summary"]);
                string parameters = "{";
                int paramCount = 0;
                JToken pathParams = path.First["post"]["parameters"].First;
                if (pathParams != null)
                {
                    try
                    {
                        foreach (JProperty prop in pathParams["schema"]["properties"])
                        {
                            if (paramCount++ > 0)
                            {
                                parameters += ",\n";
                            }
                            parameters += "   \"" + (string)prop.Name + "\": \"\"";
                        }
                    }
                    catch
                    {
                        try
                        {
                            foreach (JToken tok in pathParams.First)
                            {
                                if (tok is JProperty prop)
                                {
                                    if (paramCount++ > 0)
                                    {
                                        parameters += ",\n";
                                    }
                                    parameters += "   \"" + (string)prop + "\": \"\"";
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Ccli.WriteErrorText($"Error parsing swagger properties from {swaggerPath}: {e.Message}");
                            return false;
                        };
                    }
                }
                if (paramCount > 0)
                {
                    parameters += "\n";
                }
                parameters += "}";
                JProperty sample = new JProperty("sample", parameters);
                JObject thisCall = new JObject
                {
                    restPath,     //  path == REST endpoint
                    sample,       //  parameters
                    group,        //  Grouping of calls
                    reference,    //  Reference (not really API, misnamed)
                    desc         //  Name of call
                };
                calls.Add(thisCall);

            }
            m_apiCalls = new JObject();
            JProperty callWrapper = new JProperty("apis", calls);
            m_apiCalls.Add(callWrapper);
            return true;
        }

        /// <summary>Locate the specified API.  Could put in dict instead, but this is fine for current numbers.</summary>
        /// <param name="groupAndName"></param>
        /// <returns>API group object</returns>
        public JObject FindAPI(string groupAndName)
        {
            foreach (JObject jo in m_apiCalls["apis"])
            {
                if ((jo["group"] + ":" + jo["api"]).CompareTo(groupAndName) == 0)
                {
                    return jo;
                }
            }
            return null;
        }

        /// <summary>JObject to string</summary>
        /// <param name="jo">JObject</param>
        /// <returns>String version of JObject</returns>
        private String ApiJObjectToString(JObject jo)
        {
            StringBuilder sb = new StringBuilder();
            return sb.Append(jo["path"] + ": " + jo["reference"] + "\n")
                    .Append(jo["sample"].ToString().Replace("{", "{\n").Replace("\\n", "\n")).Append("\n\n").ToString();
        }

        /// <summary>List all APIs.</summary>
        /// <returns>API list</returns>
        public string ListAPIs()
        {
            StringBuilder sb = new StringBuilder();
            SortedSet<string> report = new SortedSet<string>();
            foreach (JObject jo in m_apiCalls["apis"])
            {
                report.Add(ApiJObjectToString(jo));
            }
            foreach (string s in report)
            {
                sb.Append(s);
            }
            return sb.ToString();
        }

        /// <summary>Returns APIs with the specified substring in their path or summary or tag</summary>
        /// <param name="subset"></param>
        /// <returns>API list</returns>
        public string FindAPIMatch(string subset)
        {
            SortedSet<string> report = new SortedSet<string>();
            foreach (JObject jo in m_apiCalls["apis"])
            {
                if ((jo["group"].ToString().Contains(subset, StringComparison.InvariantCultureIgnoreCase))
                    || (jo["path"].ToString().Contains(subset, StringComparison.InvariantCultureIgnoreCase))
                    || (jo["reference"].ToString().Contains(subset, StringComparison.InvariantCultureIgnoreCase))
                    || (jo["api"].ToString().Contains(subset, StringComparison.InvariantCultureIgnoreCase))
                    )
                {
                    report.Add(ApiJObjectToString(jo));
                }
            }
            StringBuilder sb = new StringBuilder();
            foreach (string s in report)
            {
                sb.Append(s);
            }
            return sb.ToString();
        }

        /// <summary>REST result (JObject) to string</summary>
        /// <param name="result">JObject result</param>
        /// <returns>String version of result</returns>
        private static string ResultToString(JObject result)
        {
            if (result == null)
            {
                return string.Empty;
            }

            List<string> propNames = result.Properties().Select(prop => prop.Name).ToList();
            foreach (string propName in propNames)
            {
                // Never remove "Result", always remove "IsSoftError" or null values
                switch (propName)
                {
                    case "Result":
                        break;
                    case "IsSoftError":
                        result.Remove(propName);
                        break;
                    default:
                        JToken val = result[propName];
                        if ((val == null) ||
                            (val.Type == JTokenType.Array && !val.HasValues) ||
                            (val.Type == JTokenType.Object && !val.HasValues) ||
                            (val.Type == JTokenType.String && String.IsNullOrEmpty(val.ToString())) ||
                            (val.Type == JTokenType.Null))
                        {
                            result.Remove(propName);
                        }
                        break;
                }
            }
            return JsonConvert.SerializeObject(result, Formatting.Indented);
        }

        /// <summary>Fetch value of key from JObject, if key exists</summary>
        /// <param name="obj">JObject</param>
        /// <param name="key">Key name</param>
        /// <param name="value">(out) Key value</param>
        /// <returns>Value of key, or default value if key is not present</returns>
        private bool TryGetJObjectValue<T>(JObject obj, string key, out T value)
        {
            if ((obj != null) && obj.TryGetValue(key, out JToken token))
            {
                value = token.ToObject<T>();
                return true;
            }
            else
            {
                value = default(T);
                return false;
            }
        }

        /// <summary>Parses the output and returns success or failure and the string to write to the console.</summary>
        /// <param name="restResults"></param>
        /// <returns></returns>
        public Tuple<bool, string> ParseResults(string restResults)
        {
            JObject resultSet;
            try
            {
                resultSet = ParseContentsToJObject(restResults);
                if (!TryGetJObjectValue(resultSet, "success", out bool success))
                {
                    throw new ArgumentException($"Results are missing 'success': {ResultToString(resultSet)}", "success");
                }
                return new Tuple<bool, string>(success, ResultToString(resultSet));
            }
            catch (Exception e)
            {
                return new Tuple<bool, string>(false, MakeFailResult(restResults, "REST results could not be parsed.", e.Message));
            }
        }

        /// <summary>Generate a failure result fpr a REST call.</summary>
        /// <param name="result">JToken result</param>
        /// <param name="message">Optional error message string</param>
        /// <param name="exception">Optional exception string</param>
        /// <returns>rResult string</returns>
        public static string MakeFailResult(JToken result, string message = null, string exception = null)
        {
            JObject failResult = new JObject
            {
                ["success"] = false,
                ["Message"] = (message != null ? FAILED + message : null),
                ["Exception"] = exception
            };
            return ResultToString(failResult);
        }

        /// <summary>generate a stromng of random characters.</summary>
        /// <param name="chars">Number of characters</param>
        /// <returns>Random string</returns>
        public static string RandomString(int chars)
        {
            Random r = new Random();
            string random = "";
            for (int i = 0; i < chars; i++)
            {
                int x = r.Next(62);
                random += (char)(x < 26?(char)(x+'a'):x<52?(char)(x-26+'A'):(char)x-52+'0');
            }
            return random;
        }

        /// <summary>Centrify-specific OAuth2 Token request</summary>
        /// <param name="config">Contains config info, including profile to use</param>
        /// <param name="timeout">Timeout is milliserconds for REST calls</param>
        /// <returns>Tuple of success and either token or error message.</returns>
        public async Task<Tuple<ResultCode, string>> OAuth2_GenerateTokenRequest(CentrifyCliConfig config, int timeout)
        {
            ServerProfile profile = config.Profile;
            string TokenEndpoint =  "/oauth2/token/" + profile.OAuthAppId;

            if(profile.Password == null && !config.Silent)
            {
                Console.Write($"Enter password for {profile.UserName}: ");
                profile.Password = ReadMaskedPassword(false);
            }

            string queryParams = $"grant_type=client_credentials&response_type=code&state={RandomString(15)}&scope=ccli&client_id={profile.UserName}&client_secret={profile.Password}";

            try
            {
                Ccli.ConditionalWrite($"Requesting token for {profile.UserName}.", config.Silent);
                InitializeClient(profile.URL);
                Task<HttpResponseMessage> response = m_restUpdater.NewRequestAsync(profile.URL+ TokenEndpoint, queryParams);
                if (!response.Wait(timeout))
                {
                    return new Tuple<ResultCode, string>(ResultCode.Timeout, "Request for token timed out.");
                }

                HttpStatusCode statusCode = response.Result.StatusCode;
                string contents = await response.Result.Content.ReadAsStringAsync();
                JObject resultSet = ParseContentsToJObject(contents);

                if (response.Result.StatusCode != HttpStatusCode.OK)
                {
                    return new Tuple<ResultCode, string>(ResultCode.Failed, $"Token request failed/denied: {statusCode}, {ResultToString(resultSet)}");
                }

                if (!TryGetJObjectValue(resultSet, "access_token", out string accessToken))
                {
                    throw new ArgumentException($"Token response is missing 'access_token': {ResultToString(resultSet)}", "access_token");
                }
                return new Tuple<ResultCode, string>(ResultCode.Success, accessToken);
            }
            catch (Exception ex)
            {
                return new Tuple<ResultCode, string>(ResultCode.Exception, ex.Message);
            }
        }

        /// <summary>Accepts either the token or the entire response string, parses out the token.</summary>
        /// <param name="response"></param>
        /// <returns>Parsed token</returns>
        public static string ParseToken(string response)
        {
            string tokenFlag = "access_token";
            if (!response.Contains(tokenFlag))
            {
                return response;
            }

            string[] keys = response.Split(new char[]{ '&' });
            // Length includes "="
            return keys.First(k => k.StartsWith(tokenFlag)).Substring(tokenFlag.Length + 1);
        }

        /// <summary>Initialize a new rest client.</summary>
        /// <param name="url">Cloud URL</param>
        /// <returns></returns>
        public void InitializeClient(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                throw new ArgumentException("You must specify a Cloud url with the -url argument, or save config with the url set via ‘ccli -url https://<yoururl> saveconfig’");
            }

            // Validate URL
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uriResult) || (uriResult.Scheme != Uri.UriSchemeHttps))
            {
                throw new ArgumentException($"Cloud URL is invalid (must start with 'https://'): '{url}'");
            }

            m_restUpdater.NewClient();
            m_url = url;
        }

        /// <summary>Initialize a new rest client.</summary>
        /// <param name="url">Cloud URL</param>
        /// <param name="token">)Auth token</param>
        /// <returns></returns>
        public void InitializeClient(string url, string token)
        {
            InitializeClient(url);
            m_restUpdater.AuthValue = token;
        }
    }
}
