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
                    record['violations']['context']='cookies'
                    record['violations']['snippet']['buffer-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['snippet']['buffer'])) #base64 decode
                    record['violations']['observedEntity']['value-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['value'])) #base64 decode
                    # If header is explicit then the NAP does NOT provide the "observedEntity". This
                    # This creates a problem with reporting later on, so we added the record "name"
                    # Notes: Why is parameters an array!!
                    if record['violations']['policyEntity']['cookies'][0]['type']=="wildcard"
                       record['violations']['observedEntity']['name-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['name'])) #base64 decode
                    else
                       record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['cookies'][0]['name']
                    end
                 end   
  
  
                 if record['violations']['policyEntity'].has_key?('headers')
                    record['violations']['context']='headers'
                    record['violations']['snippet']['buffer-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['snippet']['buffer'])) #base64 decode
                    record['violations']['observedEntity']['value-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['value'])) #base64 decode
                    # If header is explicit then the NAP does NOT provide the "observedEntity". This
                    # This creates a problem with reporting later on, so we added the record "name"
                    # Notes: Why is parameters an array!!
                    if record['violations']['policyEntity']['headers'][0]['type']=="wildcard"
                       record['violations']['observedEntity']['name-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['name'])) #base64 decode
                    else
                       record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['headers'][0]['name']
                    end
                 end    
  
                 if record['violations']['policyEntity'].has_key?('parameters')
                    record['violations']['context']='parameters'
                    record['violations']['snippet']['buffer-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['snippet']['buffer'])) #base64 decode
                    record['violations']['observedEntity']['value-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['value'])) #base64 decode
                    # If parameter is explicit then the NAP does NOT provide the "observedEntity". This
                    # This creates a problem with reporting later on, so we added the record "name"
                    # Notes: Why is parameters an array!!
                    if record['violations']['policyEntity']['parameters'][0]['type']=="wildcard"
                       record['violations']['observedEntity']['name-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['name'])) #base64 decode
                    else
                       record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['parameters'][0]['name']
                    end
                 end               
                 if record['violations']['policyEntity'].has_key?('urls')
                    record['violations']['context']='urls'
                    record['violations']['snippet']['buffer-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['snippet']['buffer'])) #base64 decode
                    record['violations']['observedEntity']['name-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['name'])) #base64 decode
                 end
              else
                 record['violations']['context']='request'
                 record['violations']['snippet']['buffer-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['snippet']['buffer'])) #base64 decode
              end
  
  
           when 'VIOL_PARAMETER_VALUE_METACHAR'
  
              record['violations']['observedEntity']['value-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['value'])) #base64 decode
              # If header is explicit then the NAP does NOT provide the "observedEntity". This
              # This creates a problem with reporting later on, so we added the record "name"
              # Notes: Why is parameters an array!!
              if record['violations']['policyEntity']['parameters'][0]['type']=="wildcard"
                 record['violations']['observedEntity']['name-decode']=URI.encode_www_form_component(Base64.decode64(record['violations']['observedEntity']['name'])) #base64 decode
              else
                 record['violations']['observedEntity']['name-decode']=record['violations']['policyEntity']['parameters'][0]['name']
              end
  
  
  
  
  
  
  
  
  
              #if record['violations'].has_key?('snippet')
              #end
  
              #if record.key?(@target_key)
                 #encoded_value = record[@target_key]
                 #decoded_value = Base64.decode64(encoded_value)
                 #record[@output_key] = decoded_value
              #end
        end
        record
      end  

    end
  end
end
