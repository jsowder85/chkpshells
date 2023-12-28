Repository for random shell scripts I've written to help with customization

All Scripts in this repository are:
- meant to be executed in expert mode
- can be added to cronjobs
- should be created in a path that will survive an upgrade if desired
- need to be created on the local GAiA host and given execute permissions using "chmod +x <FILENAME.sh>" or your preferred version of file permission editing


**SmartCompare**
The goal is to provide a CLI script that will capture changes made in clish configuration after you update settings from the UI.
It will collect the existing configuration, prompt you to make the changes in the webUI, and then  diff the two configs and show you the output.
The primary intended purpose right now is to help customers/partners in scripting zero-touch configurations for their customers in a more friendly and automated way.
