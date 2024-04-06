#
# Copyright 2023- Kostas Skenderidis
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "fluent/plugin/filter"

module Fluent
  module Plugin
    class NginxNapDecodeFilter < Fluent::Plugin::Filter
      Fluent::Plugin.register_filter("nginx_nap_decode", self)

      config_param :target_key, :string, default: nil
      config_param :output_key, :string, default: nil
  
      def filter(tag, time, record)
  
        case record['violations']['violation']['name']

          when 'VIOL_ATTACK_SIGNATURE'
            #Based on observedEntity we will determined if it is cookie/header/url/parameter/etc
            if record['violations'].has_key?('observedEntity')
                #If attack signature is found on cookies

                if record['violations']['policyEntity'].has_key?('cookies')
                  record['violations']['context']='cookies' #Create context that is missing
                  record['violations']['observedEntity']['value-decode']=Base64.decode64(record['violations']['observedEntity']['value'])
                  record['violations']['snippet']['buffer-decode']=Base64.decode64(record['violations']['snippet']['buffer']) if record['violations'].has_key?('snippet')
                  
                  # If header is explicit then the NAP does NOT provide the "observedEntity". This creates a problem with reporting later on, so we added the record "name"
                  if record['violations']['policyEntity']['cookies'][0]['type']=="wildcard"
                      record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) 
                  else
                      record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['cookies'][0]['name']
                  end
                end

                if record['violations']['policyEntity'].has_key?('headers')
                  record['violations']['context']='headers' #Create context that is missing
                  record['violations']['observedEntity']['value-decode']=Base64.decode64(record['violations']['observedEntity']['value'])
                  record['violations']['snippet']['buffer-decode']=Base64.decode64(record['violations']['snippet']['buffer']) if record['violations'].has_key?('snippet')

                  # If header is explicit then the NAP does NOT provide the "observedEntity". This creates a problem with reporting later on, so we added the record "name"
                  if record['violations']['policyEntity']['headers'][0]['type']=="wildcard"
                      record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name'])
                  else
                      record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['headers'][0]['name']
                  end
                end

                if record['violations']['policyEntity'].has_key?('parameters')
                  record['violations']['context']='parameters' #Create context that is missing
                  
                  record['violations']['observedEntity']['value-decode']=Base64.decode64(record['violations']['observedEntity']['value']) 
                  record['violations']['snippet']['buffer-decode']=Base64.decode64(record['violations']['snippet']['buffer']) if record['violations'].has_key?('snippet')
                  
                  # If parameter is explicit then the NAP does NOT provide the "observedEntity". This creates a problem with reporting later on, so we added the record "name"
                  if record['violations']['policyEntity']['parameters'][0]['type']=="wildcard"
                      record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) 
                  else
                      record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['parameters'][0]['name']
                  end
                end

                if record['violations']['policyEntity'].has_key?('urls')
                  record['violations']['context']='urls' #Create context that is missing
                  record['violations']['snippet']['buffer-decode']=Base64.decode64(record['violations']['snippet']['buffer']) if record['violations'].has_key?('snippet')
                  record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name'])
                end
            else
                record['violations']['context']='request'
                record['violations']['snippet']['buffer-decode']=Base64.decode64(record['violations']['snippet']['buffer']) if record['violations'].has_key?('snippet')
            end


          when 'VIOL_COOKIE_LENGTH', 'VIOL_HEADER_LENGTH', 'VIOL_URL_METACHAR'
            record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) #base64 decode

          when 'VIOL_PARAMETER_VALUE_METACHAR', 'VIOL_PARAMETER_NAME_METACHAR', 'VIOL_PARAMETER_DATA_TYPE', 'VIOL_PARAMETER_NUMERIC_VALUE', 'VIOL_PARAMETER_VALUE_LENGTH', 'VIOL_PARAMETER_ARRAY_VALUE', 'VIOL_PARAMETER_LOCATION', 'VIOL_PARAMETER_STATIC_VALUE'
            record['violations']['observedEntity']['value-decode']=Base64.decode64(record['violations']['observedEntity']['value']) #base64 decode
            # If parameter is explicit then the NAP does NOT provide the "observedEntity". This creates a problem with reporting later on, so we added the record "name"
            # Notes: Why is parameters an array!!
            if record['violations']['policyEntity']['parameters'][0]['type']=="wildcard"
                record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) #base64 decode
            else
                record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['parameters'][0]['name']
            end
          when 'VIOL_PARAMETER_EMPTY_VALUE', 'VIOL_PARAMETER'
            # If filetype is explicit then the NAP does NOT provide the "observedEntity". This creates a problem with reporting later on, so we added the record "name"
            # Notes: Why is filetypes an array!!
            if record['violations']['policyEntity']['parameters'][0]['type']=="wildcard"
                record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) #base64 decode
            else
                record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['parameters'][0]['name']
            end  
          when 'VIOL_URL_LENGTH', 'VIOL_POST_DATA_LENGTH', 'VIOL_QUERY_STRING_LENGTH', 'VIOL_REQUEST_LENGTH', 'VIOL_COOKIE_LENGTH', 'VIOL_HEADER_LENGTH'
            # If filetype is explicit then the NAP does NOT provide the "observedEntity". This creates a problem with reporting later on, so we added the record "name"
            # Notes: Why is filetypes an array!!
            if record['violations']['policyEntity']['filetypes'][0]['type']=="wildcard"
                record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) #base64 decode
            else
                record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['filetypes'][0]['name']
            end            
          when 'VIOL_EVASION'
            # if the observed entity is parameter then base64-decode the parameter
            if record['violations']['observedEntity']['scope']=="parameter"
              record['violations']['observedEntity']['name-decode']=Base64.decode64(record['violations']['observedEntity']['name']) #base64 decode
              record['violations']['observedEntity']['value-decode']=Base64.decode64(record['violations']['observedEntity']['value']) #base64 decode
            
              record['violations']['snippet']['buffer-decode']=Base64.decode64(record['violations']['snippet']['buffer']) if record['violations'].has_key?('snippet')

            end
        end
        record
      end  

    end
  end
end
