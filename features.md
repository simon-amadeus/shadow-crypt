# Future Features needed
- encrypt a single file with file name obfuscation. dycrypted file name is restored on decryption.
- encrypt multiple files with file name obfuscation. dycrypted file names are restored on decryption.
- encrypt a directory recursively with file name obfuscation. directory structure is collapsed, all files are stored in a single directory with obfuscated file names. dycrypted file names are restored on decryption. directories are also restored on decryption.
- encryptes file names can be examined without full decryption (like `ls` command).
- decrypt a single file with file name restoration.
- decrypt multiple files with file name restoration.
- text files should be editable without full decryption like "ansible-vault edit" command.
- encrypted files can be opened and read without full decryption to disk. this should work for pdf, text files, images, videos, audio files etc. like "less" command.