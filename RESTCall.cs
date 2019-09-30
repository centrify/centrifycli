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
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;

namespace CentrifyCLI
{
    class RestUpdater
    {
        /// <summary>Bearer token to use for REST calls</summary>
        public string AuthValue { get; set; } = ""; // Ref: https://developer.centrify.com/docs/advancing-the-authentication

        /// <summary>REST call data</summary>
        public class RESTCall
        {
            /// <summary>String to add to base URL</summary>
            public string Endpoint;
            /// <summary>Interpolated parameterized string for input..</summary>
            public string JsonTemplate;
        }

        /// <summary>HTTP client for REST calls.</summary>
        private HttpClient m_client = null;

        /// <summary>Create new HTTP request with form data.</summary>
        /// <param name="fullURL">Request URL</param>
        /// <param name="urlFormData">Form data</param>
        /// <returns>Task for request</returns>
        public async Task<HttpResponseMessage> NewRequestAsync(string fullURL, string urlFormData)
        {
            HttpRequestMessage request = new HttpRequestMessage()
            {
                RequestUri = new Uri(fullURL),
                Method = HttpMethod.Post,
            };
            request.Headers.Add("X-CENTRIFY-NATIVE-CLIENT", "true");
            request.Headers.Add("X-CFY-SRC", "ccli");
            StringContent content = new StringContent(urlFormData, Encoding.UTF8, "application/x-www-form-urlencoded");
            request.Content = content;
            return await m_client.SendAsync(request);
        }

        /// <summary>Create new HTTP request with json payload.</summary>
        /// <param name="baseURL">Request base URL</param>
        /// <param name="urlFormData">Request call data, endpoint and json payload</param>
        /// <returns>Task for request</returns>
        public async Task<HttpResponseMessage> NewRequestAsync(string baseURL, RESTCall callData)
        {
            HttpRequestMessage request = new HttpRequestMessage()
            {
                RequestUri = new Uri(baseURL + callData.Endpoint),
                Method = HttpMethod.Post,
            };
            request.Headers.Add("X-CENTRIFY-NATIVE-CLIENT", "true");
            request.Headers.Add("X-CFY-SRC", "ccli");
            if (AuthValue.Length > 2)
            {
                request.Headers.Add("Authorization", "Bearer " + AuthValue);
            }
            StringContent content = new StringContent(callData.JsonTemplate, Encoding.UTF8, "application/json");
            request.Content = content;
            return await m_client.SendAsync(request);
        }

        /// <summary>Create a new HTTP client.</summary>
        public void NewClient()
        {
            if (m_client != null)
            {
                m_client.Dispose();
            }
            m_client = new HttpClient { Timeout = TimeSpan.FromMinutes(6) };
            m_client.DefaultRequestHeaders.Accept.Clear();
            m_client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
        }
    }
}
