# New Platform Support Using MCUXpresso Project

This sections explains the process of adding new platform support code in NX Middleware. The following steps will describe the file / folders
where changes would be required to add support to a new platform. (say lpc55s),

## Updating boards folder

Add new platform folder in boards directory. This should match the board name added in cmake_options.cmake file.
Copy/implement the necessary files here. Ensure that I2C driver is implemented properly. (Refer existing frdmmcxn947 folder for required files and implementation).

Refer :file:`nxmw/boards/frdmmcxn947/CMakeLists.txt` and create a new cmake file - :file:`nxmw/boards/<new-board>/CMakeLists.txt` to include the relevant files of new platform from the mcu-sdk and boards dir.

## Create MCUXpresso Project

Use existing frdmmcxn947 project or any other platform as a reference and create a new project for new platform.

Remove the board specific file of old platform and add relevant files of new platform. To do do, simply delete the files which are not required and drag and drop the required files in the project explorer. Ensure that the mcu-sdk files of old platforms is replaced with new platform. Also ensure that all the indlude directories and preprocessor macros are updated in the project properties.

For more information of existing MCUX projects refer: [**MCUX Projects for NX SA**](../../mcux_project/readme.md).