
#include <yara/modules.h> //yara module api
#include <jansson.h>

#define MODULE_NAME har // necessary and must be unique


// this is where the module declares the functions and data structures that will be available for your YARA rules.
begin_declarations;

  begin_struct_array("entries");
    declare_string("pageref");
    declare_string("startedDateTime");
    declare_float("time");

    begin_struct("request");
      declare_string("method");
      declare_string("url");
      declare_string("httpVersion");

      begin_struct_array("cookies");
        declare_string("name");
        declare_string("value");
        declare_string("path");
        declare_string("domain");
        declare_string("expires");
        declare_integer("httpOnly");
        declare_integer("secure");
        declare_string("comment");
      end_struct_array("cookies");

      begin_struct_array("headers");
        declare_string("name");
        declare_string("value");
        declare_string("comment");
      end_struct_array("headers");

      begin_struct_array("queryString");
        declare_string("name");
        declare_string("value");
        declare_string("comment");
      end_struct_array("queryString");

      begin_struct("postData");
        declare_string("mimeType");
        declare_string("text");

          begin_struct_array("params");
            declare_string("name");
            declare_string("value");
            declare_string("fileName");
            declare_string("contentType");
            declare_string("comment");
          end_struct_array("params");

        declare_string("comment");
      end_struct("postData");

      declare_integer("headersSize");
      declare_integer("bodySize");
      declare_string("comment");
    end_struct("request");

    begin_struct("response");
      declare_integer("status");
      declare_string("statusText");
      declare_string("httpVersion");

      begin_struct_array("cookies");
        declare_string("name");
        declare_string("value");
        declare_string("path");
        declare_string("domain");
        declare_string("expires");
        declare_integer("httpOnly");
        declare_integer("secure");
        declare_string("comment");
      end_struct_array("cookies");

      begin_struct_array("headers");
        declare_string("name");
        declare_string("value");
        declare_string("comment");
      end_struct_array("headers");

      begin_struct("content");
        declare_integer("size");
        declare_integer("compression");
        declare_string("mimeType");
        declare_string("text");
        declare_string("encoding");
        declare_string("comment");
      end_struct("content");

      declare_string("redirectURL");
      declare_integer("headersSize");
      declare_integer("bodySize");
      declare_string("comment");
    end_struct("response");

    begin_struct("cache");
      begin_struct("beforeRequest");
      end_struct("beforeRequest");
      begin_struct("afterRequest");
      end_struct("afterRequest");
      declare_string("comment");
    end_struct("cache");

    begin_struct("timings");
      declare_float("dns");
      declare_float("connect");
      declare_float("blocked");
      declare_float("send");
      declare_float("wait");
      declare_float("receive");
      declare_float("ssl");
      declare_string("comment");
    end_struct("timings");
  end_struct_array("entries");

  // declare_string("serverIPAddress");
  // declare_string("connection");
  // declare_string("comment");

end_declarations;



// initialization and finalization are done before and after a yara run
// these functions allow you to initialize and finalize any global data structure you may need to use in your module
int module_initialize(YR_MODULE* module) 
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}



/*
Both module_load and module_unload should return ERROR_SUCCESS to indicate that everything went fine. If a different value is returned the scanning will be aborted and an error reported to the user.
*/

// This function is invoked once for each scanned file, but only if the module is imported by some rule with the 'import' directive
// this function is where your module has the opportunity to inspect the file being scanned, parse or analyze it in the way preferred, and then populate the data structures defined in the declarations section
int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_OBJECT* request_obj;
  YR_OBJECT* response_obj;
  YR_OBJECT* cache_obj;
  YR_OBJECT* timings_obj;  

  json_error_t json_error;
  json_t* summary_json;
  json_t* json;

  json = json_loadb(
      (const char*) module_data,
      module_data_size,
#if JANSSON_VERSION_HEX >= 0x020600
      JSON_ALLOW_NUL,
#else
      0,
#endif
      &json_error);

  if (json == NULL)
    return ERROR_INVALID_MODULE_DATA;

  module_object->data = (void*) json_object_get(json, "log");

  request_obj = yr_get_object(module_object, "request");
  request_obj->data = (void*) json_object_get(json, "network");

  response_obj = yr_get_object(module_object, "response");
  response_obj->data = (void*) json_object_get(json, "response");

  cache_obj = yr_get_object(module_object, "cache");
  cache_obj->data = (void*) json_object_get(json, "cache");

  timings_obj = yr_get_object(module_object, "timings");
  timings_obj->data = (void*) json_object_get(json, "timings");

  return ERROR_SUCCESS;
}


// For each call to module_load there is a corresponding call to module_unload
// This function allows your module to free any resource allocated during module_load
// perhaps the data structures that were declared above and populated during load need to be freed
int module_unload(YR_OBJECT* module_object)
{
  if(module_object->data) {
    json_decref(module_object->data);
  }
  return ERROR_SUCCESS;
}
