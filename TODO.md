# TODO

* Add validation to PasswordDatabase initialization
* Add lookup structure to PasswordDatabase to improve find by ID operations
* Work from a local database file with cloud backup/initialization
  * Local file would be considered primary
  * Changes would be persisted locally and then backed up
  * Failure to backup could cause version conflict
  * Would ease initialization on a new computer
* Use different encryption provider
  * GPG
    * Pros
      * key pairs can be used for other applications besides pypass if desired
      * stores encryption keys for you
    * Cons
      * requires installation of gpg locally, which means users need to install specific 
        dependencies and possible incompatibilities
  *  Pure python
    * Pros
      * Fewer dependencies means easier installation and lower testing overhead
    * Cons
      * key management
* Make runnable as a script
* Validity checks
* Backup previous database file