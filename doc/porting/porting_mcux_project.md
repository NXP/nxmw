# New Platform Support Using MCUXpresso Project

This sections explains the process of adding new platform support code in NX Middleware. The following steps will describe the file / folders
where changes would be required to add support to a new platform. (say lpc55s),

## Updating boards folder

Add new platform folder in boards directory (say lpcxpresso55s69).. This should match the board name added in cmake_options.cmake file.
Copy / implement the necessary files here. (Refer existing frdmmcxn947 folder).

Refer :file:`nxmw/boards/frdmmcxn947/CMakeLists.txt` and create a new cmake file - :file:`nxmw/boards/lpcxpresso55s69/CMakeLists.txt` to include the relevant files of new platform from the mcu-sdk and boards dir.

## Create MCUXpresso Project

Use existing frdmmcxn947 project or any other platform as a reference and create a new project for new platform.

Remove the board specific file of old platform and add relevant files of new platform. Also ensure that the mcu-sdk files of old platforms is replaced with new platform.