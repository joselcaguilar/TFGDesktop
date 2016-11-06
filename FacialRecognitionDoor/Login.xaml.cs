using System;
using System.Collections.Generic;
using System.IO;
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Net.Http;
using System.Net.Http.Headers;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json.Linq;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Authentication.Web;
using Windows.Security.Authentication.Web.Core;
using Windows.Security.Credentials;
using Windows.Storage;
using Windows.UI.Popups;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using System.Diagnostics;
using FacialRecognitionDoor.Helpers;
using System.Threading.Tasks;

namespace FacialRecognitionDoor
{
    public sealed partial class Login : Page
    {
        public const string resource = "00000002-0000-0000-c000-000000000000";
        public const string clientId = "731c53ea-3042-4f8d-8da3-a8fcad30fa85";
        public bool ok = false;
        private DispatcherTimer timer;
        public int elapsedTime;

        // Speech Related Variables:
        private SpeechHelper speech;

        public void PrintCache()
        {
            PrintCache printed = new PrintCache();
            string cache = printed.Cache();
            //sub = sub.Substring(sub.IndexOf('@') + 1);
            if (cache == "admin@irondoor.onmicrosoft.com")
            {
                ok = true;
            }
            else
            {
                ok = false;
            }
        }

        private async void btnSearch_Click(object sender, RoutedEventArgs e)
        {
            elapsedTime = 0;
            timer = new DispatcherTimer();
            timer.Start();
            timer.Interval = new TimeSpan(0, 0, 1); //Cuenta cada segundo
            timer.Tick += timer_Tick;

            ClearCache();
            await Search("admin", "irondoor.onmicrosoft.com");
            
            PrintCache();
            if (ok)
            {
                Frame.Navigate(typeof(MainPage));
            }
            else
            {
                //User not found
                ForgetPassword.Text = "El usuario no se encuentra en Azure Active Directory";
            }
        }

        private async void timer_Tick(object sender, object e)
        {
            elapsedTime++;
            
            if (elapsedTime == 10)
            {
                Debug.WriteLine("Te quedan 10 seg");
                await speech.Read(SpeechContants.CountDownLogin);
            }
            else if (elapsedTime == 20)
            {
                Debug.WriteLine("CountdownFinalizado");
                //Add Red GPIO Notification
                timer.Stop();
                elapsedTime = 0;
                Frame.Navigate(typeof(Login)); // Reload Login Page
            }
        }

        private void speechMediaElement_Loaded(object sender, RoutedEventArgs e)
        {
            if (speech == null)
            {
                speech = new SpeechHelper(speechMediaElement);
            }
            else
            {
                // Prevents media element from creating again the SpeechHelper when user signed off
                speechMediaElement.AutoPlay = false;
            }
        }

        public Login()
        {
            this.InitializeComponent();
        }

        static async Task Search(string searchterm, string tenant) //private
        {
            
            AuthenticationResult ar = await GetToken(tenant);
            if (ar != null)
            {
                JObject jResult = null;

                string graphResourceUri = "https://graph.windows.net";
                string graphApiVersion = "2013-11-08";

                try
                {
                    string graphRequest = String.Format(CultureInfo.InvariantCulture, "{0}/{1}/users?api-version={2}&$filter=mailNickname eq '{3}'", graphResourceUri, ar.TenantId, graphApiVersion, searchterm);
                    HttpClient client = new HttpClient();
                    HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, graphRequest);
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", ar.AccessToken);
                    HttpResponseMessage response = await client.SendAsync(request);

                    string content = await response.Content.ReadAsStringAsync();
                    jResult = JObject.Parse(content);
                }
                catch (Exception ee)
                {
                    Debug.WriteLine("Error on search");
                    Debug.WriteLine(ee.Message);
                }

                if (jResult["odata.error"] != null || jResult["value"] == null)
                {
                   Debug.WriteLine("Error on search");
                }
                if (jResult.Count == 0)
                {
                    Debug.WriteLine("No user with alias {0} found. (tenantID: {1})", searchterm, ar.TenantId);
                }
                else
                {
                    /*foreach (JObject result in jResult["value"])
                    {
                        Debug.WriteLine("User found");
                        Debug.WriteLine("-----");
                        Debug.WriteLine("displayName: {0}", (string)result["displayName"]);
                        Debug.WriteLine("givenName: {0}", (string)result["givenName"]);
                        Debug.WriteLine("surname: {0}", (string)result["surname"]);
                        Debug.WriteLine("userPrincipalName: {0}", (string)result["userPrincipalName"]);
                        Debug.WriteLine("telephoneNumber: {0}", (string)result["telephoneNumber"] == null ? "Not Listed." : (string)result["telephoneNumber"]);
                    }*/
                }
            }
            else
            {
                Debug.WriteLine("Failed to obtain a token.");
            }
        }

        static void ClearCache()
        {
            AuthenticationContext ctx = new AuthenticationContext("https://login.microsoftonline.com/common");
            ctx.TokenCache.Clear();
            //Console.ForegroundColor = ConsoleColor.Green;
            Debug.WriteLine("Token cache cleared.");
        }

        static void TestPostMessage(string message)
        {
            string urlWithAccessToken = GeneralConstants.SlackURI;
        
            SlackClient client = new SlackClient(urlWithAccessToken);

            client.PostMessage(username: "IronDoor",
                       text: "IronDoor: " + message,
                       channel: "@admin");
        }

        static async Task<AuthenticationResult> GetToken(string tenant) //static - private
        {
            AuthenticationContext ctx = null;
            if (tenant != null)
                ctx = new AuthenticationContext("https://login.microsoftonline.com/" + tenant);
            else
            {
                ctx = new AuthenticationContext("https://login.microsoftonline.com/common");
                if (ctx.TokenCache.Count > 0)
                {
                    string homeTenant = ctx.TokenCache.ReadItems().First().TenantId;
                    ctx = new AuthenticationContext("https://login.microsoftonline.com/" + homeTenant);
                }
            }
            AuthenticationResult result = null;
            try
            {
                result = await ctx.AcquireTokenSilentAsync(resource, clientId);
            }
            
            catch (Exception exc)
            {
                //var adalEx = exc.InnerException as AdalException;
                //if ((adalEx != null) && (adalEx.ErrorCode == "failed_to_acquire_token_silently"))
                if (exc is AdalException || exc.InnerException is AdalException)
                {
                    result = await GetTokenViaCode(ctx);
                }
                else
                {
                    Debug.WriteLine("Something went wrong.");
                    Debug.WriteLine("Message: " + exc.InnerException.Message + "\n");
                }
            }
            return result;
        }
        
        static async Task<AuthenticationResult> GetTokenViaCode(AuthenticationContext ctx) //static - private
        {
            AuthenticationResult result = null;
            try
            {
                DeviceCodeResult codeResult = await ctx.AcquireDeviceCodeAsync(resource, clientId);
                TestPostMessage(codeResult.Message);
                //Debug.WriteLine("You need to sign in.");
                //Debug.WriteLine("Message: " + codeResult.Message + "\n");
                result = await ctx.AcquireTokenByDeviceCodeAsync(codeResult);
            }
            catch (Exception exc)
            {
                Debug.WriteLine("Something went wrong.");
                Debug.WriteLine("Message: " + exc.Message + "\n");
            }
            return result;
        }
    }
}
