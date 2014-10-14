Backup/CryptSikyur-Archiver
===========================

Tool for creating encrypted backups and archives suitable for cloud storage.

All project files are set up for Microsoft Visual Studio 2005.

The tool itself resides in subdirectory Backup. A brief summary of features:
- Dynamic pack mode - creates a multi-segment archive supporting partial updates, suitable for synchronizing to a cloud storage
    * Includes integration with Microsoft OneDrive and Google Drive
- Encryption and integrity support for pack and dynamic pack modes
    * ciphers: AES-128, Serpent-256 ThreeFish-1024 with SHA-256-HMAC integrity validation
- Decremental backup mode to local drive on file granularity (most recent checkpoint is simply a filesystem copy)
- Syncronize two local file hierarchies
- Pack mode (like tar)

Documentation and security analysis can be found in the program directory (Backup/Backup/*.rtf)

A suite of regression and coverage tests is found in subdirectory BackupTest. The VS2005 project is set up to run the suite of tests. There is an option to run code coverage using OpenCover by uncommenting the "opencover" line near the top of each file. (You must install and configure OpenCover first.)

The test tool resides in subdirectory FileUtilityTester and supports a simple scripting language oriented to testing commands that operate on files.
