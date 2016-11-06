﻿using System;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.Devices.Client;
using Newtonsoft.Json;

static class AzureIoTHub
{
    //
    // Note: this connection string is specific to the device "RPi3". To configure other devices,
    // see information on iothub-explorer at http://aka.ms/iothubgetstartedVSCS
    //
    const string deviceConnectionString = "HostName=IronDoorIoTHub.azure-devices.net;DeviceId=RPi3;SharedAccessKey=l8w+FjbnKbiEj8FkeB3GG8Hx1Z1AnmInBCzMRHRdXyc=";

    //
    // To monitor messages sent to device "RPi3" use iothub-explorer as follows:
    //    iothub-explorer HostName=IronDoorIoTHub.azure-devices.net;SharedAccessKeyName=service;SharedAccessKey=ThXHXUgzRlJ96mImvEfaWyAxa+2S5g7qsfaBmxVuA08= monitor-events "RPi3"
    //

    // Refer to http://aka.ms/azure-iot-hub-vs-cs-wiki for more information on Connected Service for Azure IoT Hub

    public static async Task SendDeviceToCloudMessageAsync(string username, int confidence, Task<string> humorstatus)
    {
        var deviceClient = DeviceClient.CreateFromConnectionString(deviceConnectionString, TransportType.Amqp);

#if WINDOWS_UWP
        //Original String from AzureIoTHub Nuget Package
        //var str = "Hello, Cloud from a UWP C# app!";
        var date = DateTime.Now;
        var year = date.Year;
        var month = date.Month;
        var day = date.Day;
        var hora = date.Hour;
        var minutes = date.Minute;
        var seconds = date.Second;
        //Format Time
        string tiempo = hora.ToString("00")+":"+minutes.ToString("00")+":"+seconds.ToString("00");

        var data = new
        {
            Dia = day.ToString(),
            Mes = month.ToString(),
            Año = year.ToString(),
            Hora = tiempo,
            Alias = username,
            Confianza = confidence,
            Humor = humorstatus.Result
        };
#else
        //var str = "Hello, Cloud from a C# app!";
#endif
        //Original String from AzureIoTHub Nuget Package
        //var message = new Message(Encoding.ASCII.GetBytes(str));
        var message = new Message(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(data)));
        await deviceClient.SendEventAsync(message);
    }
    
    public static async Task SendTemperatureAsync(int temperature)
    {
        var deviceClient = DeviceClient.CreateFromConnectionString(deviceConnectionString, TransportType.Amqp);

        var date = DateTime.Now;
        var year = date.Year;
        var month = date.Month;
        var day = date.Day;
        var hora = date.Hour;
        var minutes = date.Minute;
        var seconds = date.Second;
        //Format Time
        string tiempo = hora.ToString("00") + ":" + minutes.ToString("00") + ":" + seconds.ToString("00");

        var data = new
        {
            TDia = day.ToString(),
            TMes = month.ToString(),
            TAño = year.ToString(),
            THora = tiempo,
            Temperatura = temperature
        };
        //Original String from AzureIoTHub Nuget Package
        //var message = new Message(Encoding.ASCII.GetBytes(str));
        var message = new Message(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(data)));
        await deviceClient.SendEventAsync(message);
    }
    
    public static async Task<string> ReceiveCloudToDeviceMessageAsync()
    {
        var deviceClient = DeviceClient.CreateFromConnectionString(deviceConnectionString, TransportType.Amqp);

        while (true)
        {
            var receivedMessage = await deviceClient.ReceiveAsync();

            if (receivedMessage != null)
            {
                var messageData = Encoding.ASCII.GetString(receivedMessage.GetBytes());
                await deviceClient.CompleteAsync(receivedMessage);
                return messageData;
            }
            await Task.Delay(TimeSpan.FromSeconds(1));
        }
    }
}
