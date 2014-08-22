SecureArchiver
==============

Tool for creating encrypted backups and archives suitable for cloud storage.

All projects are set up for Microsoft Visual Studio 2005.

The tool itself resides in subdirectory Backup. A brief summary of features:
- Decremental backup mode on file basis (most recent checkpoint is simply a filesystem copy)
- Syncronize two filesystems
- Pack mode (like tar)
- Dynamic pack mode - creates multi-segment archive supporting partial updates, suitable for synchronizing to a cloud storage
- Encryption and integrity support for pack and dynamic pack modes
Documentation and security analysis can be found in the program directory (Backup/Backup/*.rtf)

A suite of unit tests is found in subdirectory BackupTest. The VS2005 project is set up to run the suite of tests. There is an option to run code coverage suing OpenCover by uncommenting the "opencover backup" line in each file. Of course, you must install OpenCover yourself.

The test tool resides in subdirectory FileUtilityTester and supports a simple scripting language oriented to testing commands that operate on files.
