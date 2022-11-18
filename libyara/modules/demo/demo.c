
#include <yara/modules.h> //yara module api

#define MODULE_NAME demo // necessary and must be unique


// this is where the module declares the functions and data structures that will be available for your YARA rules.
begin_declarations 
  declare_string("greeting");
end_declarations


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
  yr_set_string("Hello World!", module_object, "greeting");

  return ERROR_SUCCESS;
}


// For each call to module_load there is a corresponding call to module_unload
// This function allows your module to free any resource allocated during module_load
// perhaps the data structures that were declared above and populated during load need to be freed
int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
