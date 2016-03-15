/*
 * Licensed under the EUPL, Version 1.1 or – as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence. You may
 * obtain a copy of the Licence at:
 * 
 * http://www.osor.eu/eupl/european-union-public-licence-eupl-v.1.1
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * Licence for the specific language governing permissions and limitations under
 * the Licence.
 */
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;
using NLog;

//
// author: AMA – Agência para a Modernização Administrativa IP, PORTUGAL (www.ama.pt)
//
namespace eu.stork.peps.auth.commons
{
    public class ConfigurationSettingsHelper
    {
        private static Logger _logger = LogManager.GetCurrentClassLogger();
        private static engine.Properties.Settings _settings = engine.Properties.Settings.Default;

        public static string GetCriticalConfigSetting(string key)
        {
            string value;
            if (((value = _settings.Properties.OfType<SettingsProperty>().FirstOrDefault(v => v.Name == key)?.DefaultValue.ToString()) == null)
                && ((value = ConfigurationManager.AppSettings[key]) == null))
            {
                //LoggingAPI.InsertLog((int)ComponentCodeLogging.IDPCore, Source.GENERAL, LoggingType.Fatal, 
                //    "FATAL: Application Terminated! Critical configuration key '" + key + "' was not found.");
                //System.Environment.Exit(-1);
                _logger.Error("Not found: {0}", key);
                throw new KeyNotFoundException(key);
            }
            return value;
        }

        public static bool GetCriticalConfigBoolSetting(string key)
        {
            bool result, success = bool.TryParse(GetCriticalConfigSetting(key), out result);
            if (!success)
            {
                //LoggingAPI.InsertLog((int)ComponentCodeLogging.IDPCore, Source.GENERAL, LoggingType.Fatal,
                //    "FATAL: Application Terminated! Critical configuration key '" + key + "' was not found.");
                //System.Environment.Exit(-1);
                _logger.Error("Not found: {0}", key);
                throw new KeyNotFoundException(key);
            }
            return result;
        }

        public static int GetCriticalConfigIntSetting(string key)
        {
            int result;
            bool success = int.TryParse(GetCriticalConfigSetting(key), out result);
            if (!success)
            {
                //LoggingAPI.InsertLog((int)ComponentCodeLogging.IDPCore, Source.GENERAL, LoggingType.Fatal,
                //    "FATAL: Application Terminated! Critical configuration key '" + key + "' was not found.");
                //System.Environment.Exit(-1);
                _logger.Error("Not found: {0}", key);
                throw new KeyNotFoundException(key);
            }
            return result;
        }

        public static bool? GetConfigBoolSetting(string key)
        {
            bool result, success = bool.TryParse(GetConfigurationSetting(key), out result);
            if (!success)
                return null;
            return result;
        }

        public static int? GetConfigIntSetting(string key)
        {
            int result;
            bool success = int.TryParse(GetConfigurationSetting(key), out result);
            if (!success)
                return null;
            return result;
        }

        /// <summary>
        /// Gets the configuration setting.
        /// </summary>
        /// <param name="key">The configuration setting key.</param>
        /// <returns></returns>
        public static string GetConfigurationSetting(string key)
        {
            string value;
            if (((value = _settings.PropertyValues.OfType<SettingsPropertyValue>().FirstOrDefault(v => v.Name == key)?.PropertyValue.ToString()) == null)
                && ((value = ConfigurationManager.AppSettings[key]) == null))
            {
                _logger.Debug("NULL VALUE FOR KEY {0};", key);
                return string.Empty;
            }
            else
            {
                return value;
            }
        }

    }
}
