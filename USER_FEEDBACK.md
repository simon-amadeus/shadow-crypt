# USER FEEDBACK

- by saying "when listing encrypted filed users can't tell which file is which" meant that the list in cryptls only shows the original filenames but not which obfuscated name corresponds to which original name. so when a user wants to decrypt a specific file they can't tell which obfuscated filename to use. the list should show both the obfuscated filename and the original filename (if it can be decrypted with the provided password). if the original filename can't be decrypted (wrong password or corrupted) it should indicate that as well.

- add an --inplace option to lock and unlock to overwrite the original file after successful encryption/decryption. this is a common use case and would simplify workflows.

- when the user does not use the inplace option encrypting and decrypting a file the original file and the encrypted file exist. so when the encrypted one is being decrypted the original file is overridden without warning. i this this should be prevented by default and only allowed with an explicit --force flag. 